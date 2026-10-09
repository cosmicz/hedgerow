// Senso guidance adapter (optional; server-side only).
//
// Senso holds one public, demo-only guidance document (guidance.md) and
// answers a small fixed set of interpretation questions from it, with every
// passage cited by its Senso content_id. It never receives household data:
// queries come from an allowlisted topic enum, never from free text, logs or
// observations. It has no action authority and its answers are shown as
// guidance, not as evidence.
//
// Official API: https://docs.senso.ai/docs/quickstart and specs/sdk-api.yaml.
// The base URL is a constant (no configurable endpoint), every request uses
// redirect: "error" and a timeout, and the API key is read server-side from
// the rig .env and never logged or returned.
import { readFileSync } from "node:fs";

export const SENSO_API_BASE = "https://apiv2.senso.ai/api/v1";

export const GUIDANCE_QUERIES = Object.freeze({
  "dns-deny-limits": "What does a DNS deny rule not do, and what does verification measure?",
  "measured-vs-model": "How should measured evidence and a model judgment be interpreted when they disagree?",
} as const);

/** Retrieval bounds: a useful answer has 1..MAX_PASSAGES validated passages of bounded length. */
export const MAX_PASSAGES = 3;
export const MAX_PASSAGE_CHARS = 2_000;

export type GuidanceTopic = keyof typeof GUIDANCE_QUERIES;

export interface GuidanceDocument {
  readonly sha256: string;
  readonly title: string;
  readonly content_id: string;
  readonly kb_node_id: string;
}

export interface GuidancePassage {
  readonly content_id: string;
  readonly kb_node_id: string;
  readonly title: string;
  readonly text: string;
  readonly score: number;
  readonly rank: number;
}

export type GuidanceResult =
  | {
      readonly status: "ok";
      readonly topic: GuidanceTopic;
      readonly query: string;
      readonly passages: readonly GuidancePassage[];
      /** Distinct Senso content_ids the passages came from; always our guidance document. */
      readonly citations: readonly string[];
      readonly document: GuidanceDocument;
      readonly latency_ms: number;
    }
  | { readonly status: "unavailable" | "error"; readonly topic: GuidanceTopic; readonly reason: string };

export interface SensoStatus {
  readonly sponsor: "senso";
  readonly health: "ok" | "degraded" | "unavailable";
  readonly detail: string;
  readonly document: GuidanceDocument | null;
}

export interface SensoDeps {
  readonly fetch?: typeof fetch;
  readonly sleep?: (ms: number) => Promise<void>;
  readonly timeoutMs?: number;
  /** Poll attempts while Senso processes the document (5 s apart per the docs). */
  readonly pollAttempts?: number;
  readonly pollIntervalMs?: number;
}

/** Fixed display labels: errors name the route, never the actual path (which may hold server-returned ids). */
const ROUTES = {
  ingest: "POST /org/kb/raw",
  find: "GET /org/kb/find",
  node: "GET /org/kb/nodes/:id",
  context: "POST /org/search/context",
} as const;

type Route = (typeof ROUTES)[keyof typeof ROUTES];

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class SensoError extends Error {
  override readonly name = "SensoError";
}

/** Reads only SENSO_API_KEY from a dotenv file; any other line is ignored. Missing file or key → null. */
export function readSensoKey(envPath: string): string | null {
  let text: string;
  try {
    text = readFileSync(envPath, "utf8");
  } catch {
    return null;
  }
  for (const line of text.split("\n")) {
    const match = /^\s*(?:export\s+)?SENSO_API_KEY\s*=\s*(.*)\s*$/.exec(line);
    if (match) {
      const value = match[1]!.replace(/^(['"])(.*)\1$/, "$2").trim();
      return value.length > 0 ? value : null;
    }
  }
  return null;
}

export function guidanceText(): string {
  return readFileSync(new URL("./guidance.md", import.meta.url), "utf8");
}

export class SensoGuidance {
  readonly #key: string | null;
  readonly #text: string;
  readonly #fetch: typeof fetch;
  readonly #sleep: (ms: number) => Promise<void>;
  readonly #timeoutMs: number;
  readonly #pollAttempts: number;
  readonly #pollIntervalMs: number;
  #document: GuidanceDocument | null = null;
  #lastError: string | null = null;

  /** The uploaded text is always the fixed public guidance.md; callers cannot supply other content. */
  constructor(key: string | null, deps: SensoDeps = {}) {
    this.#key = key;
    this.#text = guidanceText();
    this.#fetch = deps.fetch ?? fetch;
    this.#sleep = deps.sleep ?? ((ms) => Bun.sleep(ms));
    this.#timeoutMs = deps.timeoutMs ?? 10_000;
    this.#pollAttempts = deps.pollAttempts ?? 12;
    this.#pollIntervalMs = deps.pollIntervalMs ?? 5_000;
  }

  /** For servers that already load .env (e.g. Bun): reads SENSO_API_KEY from the given environment. */
  static fromEnv(env: Readonly<Record<string, string | undefined>> = process.env, deps: SensoDeps = {}): SensoGuidance {
    const key = env.SENSO_API_KEY?.trim();
    return new SensoGuidance(key ? key : null, deps);
  }

  /** For scripts: reads only SENSO_API_KEY from a dotenv file. */
  static fromEnvFile(envPath: string, deps: SensoDeps = {}): SensoGuidance {
    return new SensoGuidance(readSensoKey(envPath), deps);
  }

  /** Ingests the guidance document once (idempotent across restarts) and waits until it is searchable. */
  async ensureDocument(): Promise<GuidanceDocument> {
    if (this.#document) {
      return this.#document;
    }
    if (!this.#key) {
      throw new SensoError("not configured");
    }
    const sha256 = new Bun.CryptoHasher("sha256").update(this.#text).digest("hex");
    // The hash in the title makes the document findable after a restart (Senso answers 409 for duplicate text).
    const title = `Hedgerow demo guidance ${sha256.slice(0, 12)}`;
    let ids: { content_id: string; kb_node_id: string };
    const created = await this.#request(ROUTES.ingest, "/org/kb/raw", { title, text: this.#text }, [202, 409]);
    if (created.status === 202) {
      ids = { content_id: uuidField(created.body, "id"), kb_node_id: uuidField(created.body, "kb_node_id") };
    } else {
      ids = await this.#findByTitle(title);
    }
    await this.#waitUntilComplete(ids.kb_node_id);
    this.#document = { sha256, title, ...ids };
    return this.#document;
  }

  async guidance(topic: GuidanceTopic): Promise<GuidanceResult> {
    if (!Object.hasOwn(GUIDANCE_QUERIES, topic)) {
      return { status: "error", topic, reason: "unknown topic" };
    }
    if (!this.#key) {
      return { status: "unavailable", topic, reason: "not configured" };
    }
    const started = performance.now();
    try {
      const document = await this.ensureDocument();
      const query = GUIDANCE_QUERIES[topic];
      const { body } = await this.#request(ROUTES.context, "/org/search/context", {
        query,
        max_results: MAX_PASSAGES,
        content_ids: [document.content_id],
        require_scoped_ids: true,
      }, [200]);
      const passages = validatePassages(body, document);
      this.#lastError = null;
      return {
        status: "ok",
        topic,
        query,
        passages,
        citations: [...new Set(passages.map((passage) => passage.content_id))],
        document,
        latency_ms: Math.round(performance.now() - started),
      };
    } catch (error) {
      this.#lastError = (error as Error).message.slice(0, 200);
      return { status: "error", topic, reason: this.#lastError };
    }
  }

  status(): SensoStatus {
    if (!this.#key) {
      return { sponsor: "senso", health: "unavailable", detail: "Senso unavailable (not configured)", document: null };
    }
    if (this.#lastError) {
      return { sponsor: "senso", health: "degraded", detail: `Senso error (${this.#lastError})`, document: this.#document };
    }
    return {
      sponsor: "senso",
      health: this.#document ? "ok" : "degraded",
      detail: this.#document ? "Guidance document ingested; cited retrieval available" : "Guidance document not yet ingested",
      document: this.#document,
    };
  }

  async #findByTitle(title: string): Promise<{ content_id: string; kb_node_id: string }> {
    const { body } = await this.#request(ROUTES.find, `/org/kb/find?q=${encodeURIComponent(title)}&limit=20`, undefined, [200]);
    const node = arrayField(body, "nodes").find(
      (entry) => isRecord(entry) && entry.name === title && entry.type === "content" && typeof entry.content_id === "string",
    ) as Record<string, unknown> | undefined;
    if (!node) {
      throw new SensoError("duplicate reported but guidance document not found by title");
    }
    return { content_id: uuidField(node, "content_id"), kb_node_id: uuidField(node, "kb_node_id") };
  }

  async #waitUntilComplete(kbNodeId: string): Promise<void> {
    for (let attempt = 0; attempt < this.#pollAttempts; attempt++) {
      const { body } = await this.#request(ROUTES.node, `/org/kb/nodes/${encodeURIComponent(kbNodeId)}`, undefined, [200]);
      const content = isRecord(body) && isRecord(body.content) ? body.content : {};
      if (content.processing_status === "complete") {
        return;
      }
      if (content.processing_status === "failed") {
        // Senso's error_code is server-controlled text; report a fixed local message.
        throw new SensoError("ingestion failed");
      }
      await this.#sleep(this.#pollIntervalMs);
    }
    throw new SensoError("guidance document still processing");
  }

  async #request(route: Route, path: string, body: unknown, expected: readonly number[]): Promise<{ status: number; body: unknown }> {
    const method = route.split(" ")[0]!;
    let response: Response;
    try {
      response = await this.#fetch(`${SENSO_API_BASE}${path}`, {
        method,
        headers: { "X-API-Key": this.#key!, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
        body: body === undefined ? undefined : JSON.stringify(body),
        redirect: "error",
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch {
      throw new SensoError(`${route} request failed`);
    }
    if (!expected.includes(response.status)) {
      // Status only: response bodies are not echoed into UI-visible errors.
      throw new SensoError(`${route} returned HTTP ${response.status}`);
    }
    // Response bodies never reach reasons or status: parse failures get a fixed local message.
    let parsed: unknown = null;
    try {
      const text = await response.text();
      parsed = text ? (JSON.parse(text) as unknown) : null;
    } catch {
      throw new SensoError(`${route} returned a malformed response`);
    }
    return { status: response.status, body: parsed };
  }
}

/**
 * A useful answer is 1..MAX_PASSAGES passages, each from our guidance document,
 * with a finite score, a positive integer rank and non-empty text capped at
 * MAX_PASSAGE_CHARS. Anything else is an error with a fixed message; an empty
 * or malformed result is never reported as "ok".
 */
function validatePassages(body: unknown, document: GuidanceDocument): GuidancePassage[] {
  if (!isRecord(body) || !Array.isArray(body.results)) {
    throw new SensoError("malformed retrieval result");
  }
  if (body.results.length === 0) {
    throw new SensoError("no guidance passages returned");
  }
  if (body.results.length > MAX_PASSAGES) {
    throw new SensoError("retrieval returned more passages than requested");
  }
  return body.results.map((entry): GuidancePassage => {
    if (!isRecord(entry)) {
      throw new SensoError("malformed retrieval result");
    }
    // Scoped retrieval must only return our document; anything else is refused, not shown.
    if (entry.content_id !== document.content_id) {
      throw new SensoError("retrieval returned content outside the guidance document");
    }
    const { kb_node_id, title, chunk_text, score, rank } = entry;
    if (typeof kb_node_id !== "string" || !UUID.test(kb_node_id) || typeof chunk_text !== "string" || chunk_text.trim().length === 0 ||
      typeof score !== "number" || !Number.isFinite(score) ||
      typeof rank !== "number" || !Number.isInteger(rank) || rank < 1 || rank > MAX_PASSAGES) {
      throw new SensoError("malformed retrieval result");
    }
    return {
      content_id: document.content_id,
      kb_node_id,
      title: typeof title === "string" ? title.slice(0, 200) : "",
      text: chunk_text.slice(0, MAX_PASSAGE_CHARS),
      score,
      rank,
    };
  });
}

function stringField(value: unknown, field: string): string {
  if (isRecord(value) && typeof value[field] === "string" && value[field]) {
    return value[field] as string;
  }
  throw new SensoError(`response missing ${field}`);
}

/** Server-returned ids are used in request paths and citations, so they must be UUIDs. */
function uuidField(value: unknown, field: string): string {
  const id = stringField(value, field);
  if (!UUID.test(id)) {
    throw new SensoError(`response has an invalid ${field}`);
  }
  return id;
}

function arrayField(value: unknown, field: string): unknown[] {
  return isRecord(value) && Array.isArray(value[field]) ? (value[field] as unknown[]) : [];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
