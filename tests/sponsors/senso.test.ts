// Senso: one public guidance document, two fixed topics, scoped cited
// retrieval, and truthful unavailable/error states. Stubbed fetch; no network.
import { describe, expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  GUIDANCE_QUERIES,
  MAX_PASSAGE_CHARS,
  SENSO_API_BASE,
  SensoGuidance,
  guidanceText,
  readSensoKey,
} from "../../src/adapters/sponsors/senso/index.js";

const KEY = "tgr_test_secret_key";
const CONTENT = "6c1f2a9e-3b4d-4e8f-9a7b-1c2d3e4f5a6b";
const NODE = "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b";

interface Call { method: string; url: string; headers: Record<string, string>; body: unknown; redirect: RequestRedirect | undefined }

/** Minimal Senso: answers by route; records every request. */
function stubSenso(options: {
  duplicate?: boolean;
  foreignResult?: boolean;
  processing?: string[];
  searchStatus?: number;
  /** Raw search response body (string bodies are sent as-is, e.g. non-JSON). */
  searchBody?: unknown;
  failedErrorCode?: string;
  /** kb_node_id the ingest response returns (hostile-id tests). */
  ingestNodeId?: string;
  nodeFailure?: "http" | "transport" | "malformed";
} = {}) {
  const calls: Call[] = [];
  const statuses = [...(options.processing ?? ["complete"])];
  const fetch = (async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    calls.push({ method, url, headers: init?.headers as Record<string, string>, body: init?.body ? JSON.parse(String(init.body)) : undefined, redirect: init?.redirect });
    const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });
    const path = url.slice(SENSO_API_BASE.length);
    if (method === "POST" && path === "/org/kb/raw") {
      return options.duplicate ? json(409, { error: "duplicate" }) : json(202, { id: CONTENT, kb_node_id: options.ingestNodeId ?? NODE, processing_status: "processing" });
    }
    if (method === "GET" && path.startsWith("/org/kb/find?")) {
      const title = new URL(url).searchParams.get("q");
      return json(200, { nodes: [{ kb_node_id: NODE, content_id: CONTENT, type: "content", name: title }], total: 1, limit: 20, offset: 0 });
    }
    if (method === "GET" && path.startsWith("/org/kb/nodes/")) {
      if (options.nodeFailure === "http") return json(500, { error: "x" });
      if (options.nodeFailure === "transport") throw new TypeError(`connect failed ${path}`);
      if (options.nodeFailure === "malformed") return new Response(`not json ${path}`, { status: 200 });
      if (options.failedErrorCode) {
        return json(200, { kb_node_id: NODE, type: "content", content: { processing_status: "failed", error_code: options.failedErrorCode } });
      }
      return json(200, { kb_node_id: NODE, type: "content", content: { processing_status: statuses.shift() ?? "complete" } });
    }
    if (method === "POST" && path === "/org/search/context") {
      if (options.searchStatus) return json(options.searchStatus, { error: "x" });
      if (typeof options.searchBody === "string") return new Response(options.searchBody, { status: 200 });
      if (options.searchBody !== undefined) return json(200, options.searchBody);
      return json(200, {
        results: [
          { content_id: CONTENT, kb_node_id: NODE, title: "Hedgerow demo guidance", chunk_text: "A DNS deny rule does not end connections that already exist.", score: 0.9, rank: 1 },
          ...(options.foreignResult ? [{ content_id: "other", kb_node_id: "x", chunk_text: "private", score: 0.1, rank: 2 }] : []),
        ],
      });
    }
    return json(404, {});
  }) as unknown as typeof globalThis.fetch;
  return { calls, fetch };
}

const fast = { sleep: async () => {}, pollIntervalMs: 0 };

describe("senso guidance", () => {
  test("ingests the public document, then returns scoped passages cited by content_id", async () => {
    const { calls, fetch } = stubSenso({ processing: ["processing", "complete"] });
    const senso = new SensoGuidance(KEY, { fetch, ...fast });

    const result = await senso.guidance("dns-deny-limits");

    expect(result).toMatchObject({ status: "ok", topic: "dns-deny-limits", query: GUIDANCE_QUERIES["dns-deny-limits"], citations: [CONTENT] });
    expect(result.status === "ok" && result.passages[0]).toMatchObject({ content_id: CONTENT, rank: 1 });
    expect(calls.map((call) => `${call.method} ${call.url.slice(SENSO_API_BASE.length).split("?")[0]}`)).toEqual([
      "POST /org/kb/raw",
      `GET /org/kb/nodes/${NODE}`,
      `GET /org/kb/nodes/${NODE}`,
      "POST /org/search/context",
    ]);
    const search = calls.at(-1)!;
    expect(search.body).toEqual({ query: GUIDANCE_QUERIES["dns-deny-limits"], max_results: 3, content_ids: [CONTENT], require_scoped_ids: true });
    expect(calls.every((call) => call.redirect === "error" && call.url.startsWith(SENSO_API_BASE) && call.headers["X-API-Key"] === KEY)).toBe(true);
    expect(senso.status()).toMatchObject({ health: "ok", document: { content_id: CONTENT, kb_node_id: NODE } });
  });

  test("the document is ingested once; later topics reuse it", async () => {
    const { calls, fetch } = stubSenso();
    const senso = new SensoGuidance(KEY, { fetch, ...fast });
    await senso.guidance("dns-deny-limits");
    await senso.guidance("measured-vs-model");

    expect(calls.filter((call) => call.url.endsWith("/org/kb/raw"))).toHaveLength(1);
    expect(calls.filter((call) => call.url.endsWith("/org/search/context"))).toHaveLength(2);
  });

  test("after a restart, a duplicate (409) is resolved by the hash-stamped title", async () => {
    const { calls, fetch } = stubSenso({ duplicate: true });
    const senso = new SensoGuidance(KEY, { fetch, ...fast });

    const document = await senso.ensureDocument();

    expect(document).toMatchObject({ content_id: CONTENT, kb_node_id: NODE });
    expect(document.title).toMatch(/^Hedgerow demo guidance [0-9a-f]{12}$/);
    expect(new URL(calls[1]!.url).searchParams.get("q")).toBe(document.title);
  });

  test("retrieval outside the guidance document is refused, not shown", async () => {
    const { fetch } = stubSenso({ foreignResult: true });
    const senso = new SensoGuidance(KEY, { fetch, ...fast });

    const result = await senso.guidance("measured-vs-model");

    expect(result).toEqual({ status: "error", topic: "measured-vs-model", reason: "retrieval returned content outside the guidance document" });
    expect(senso.status().health).toBe("degraded");
  });

  test("no key: unavailable without any request", async () => {
    const { calls, fetch } = stubSenso();
    const senso = new SensoGuidance(null, { fetch, ...fast });

    expect(await senso.guidance("dns-deny-limits")).toEqual({ status: "unavailable", topic: "dns-deny-limits", reason: "not configured" });
    expect(senso.status()).toMatchObject({ health: "unavailable" });
    expect(calls).toEqual([]);
  });

  test("API errors report status only and never leak the key; unknown topics are rejected", async () => {
    const { calls, fetch } = stubSenso({ searchStatus: 402 });
    const senso = new SensoGuidance(KEY, { fetch, ...fast });

    const result = await senso.guidance("dns-deny-limits");
    const unknown = await senso.guidance("anything the user typed" as never);

    expect(result).toEqual({ status: "error", topic: "dns-deny-limits", reason: "POST /org/search/context returned HTTP 402" });
    expect(JSON.stringify([result, senso.status()])).not.toContain(KEY);
    expect(unknown).toMatchObject({ status: "error", reason: "unknown topic" });
    expect(calls.filter((call) => call.url.endsWith("/org/search/context"))).toHaveLength(1);
  });

  test("ingestion that never completes is an error, bounded", async () => {
    const { fetch } = stubSenso({ processing: Array(10).fill("processing") });
    const senso = new SensoGuidance(KEY, { fetch, ...fast, pollAttempts: 3 });

    expect(await senso.guidance("dns-deny-limits")).toMatchObject({ status: "error", reason: "guidance document still processing" });
  });

  test("key sources: env object and dotenv file read only SENSO_API_KEY", () => {
    const dir = mkdtempSync(join(tmpdir(), "rg-senso-"));
    writeFileSync(join(dir, ".env"), `OTHER_SECRET=x\nexport SENSO_API_KEY="${KEY}"\n`);
    writeFileSync(join(dir, "empty.env"), "OTHER_SECRET=x\n");

    expect(readSensoKey(join(dir, ".env"))).toBe(KEY);
    expect(readSensoKey(join(dir, "empty.env"))).toBeNull();
    expect(readSensoKey(join(dir, "missing.env"))).toBeNull();
    expect(SensoGuidance.fromEnv({}).status().health).toBe("unavailable");
    expect(SensoGuidance.fromEnv({ SENSO_API_KEY: KEY }).status().health).toBe("degraded");
  });

  test("the public guidance document carries no addresses or credentials", async () => {
    const text = await Bun.file(join(import.meta.dir, "../../src/adapters/sponsors/senso/guidance.md")).text();
    expect(text).not.toMatch(/\b\d{1,3}(\.\d{1,3}){3}\b|[0-9a-f]{2}(:[0-9a-f]{2}){5}|password|api[_-]?key|tgr_/i);
    expect(text).toContain("DNS deny rule");
  });

  test("server-controlled content never reaches reason or status (hostile markers)", async () => {
    const parse = stubSenso({ searchBody: "PRIVATE_RESPONSE_MARKER not json" });
    const a = new SensoGuidance(KEY, { fetch: parse.fetch, ...fast });
    const malformed = await a.guidance("dns-deny-limits");

    const failed = stubSenso({ failedErrorCode: "PRIVATE_ERROR_CODE_MARKER" });
    const b = new SensoGuidance(KEY, { fetch: failed.fetch, ...fast });
    const ingest = await b.guidance("dns-deny-limits");

    expect(malformed).toEqual({ status: "error", topic: "dns-deny-limits", reason: "POST /org/search/context returned a malformed response" });
    expect(ingest).toEqual({ status: "error", topic: "dns-deny-limits", reason: "ingestion failed" });
    const visible = JSON.stringify([malformed, a.status(), ingest, b.status()]);
    expect(visible).not.toContain("PRIVATE_RESPONSE_MARKER");
    expect(visible).not.toContain("PRIVATE_ERROR_CODE_MARKER");
  });

  test.each([
    ["no passages", { results: [] }, "no guidance passages returned"],
    ["results not an array", { results: "x" }, "malformed retrieval result"],
    ["missing results", {}, "malformed retrieval result"],
    ["non-finite score", { results: [{ content_id: CONTENT, kb_node_id: NODE, chunk_text: "t", score: "NaN", rank: 1 }] }, "malformed retrieval result"],
    ["rank out of range", { results: [{ content_id: CONTENT, kb_node_id: NODE, chunk_text: "t", score: 0.5, rank: 0 }] }, "malformed retrieval result"],
    ["empty text", { results: [{ content_id: CONTENT, kb_node_id: NODE, chunk_text: "  ", score: 0.5, rank: 1 }] }, "malformed retrieval result"],
    ["too many passages", { results: [1, 2, 3, 4].map((rank) => ({ content_id: CONTENT, kb_node_id: NODE, chunk_text: "t", score: 0.5, rank })) }, "retrieval returned more passages than requested"],
  ])("%s is an error, never ok", async (_label, body, reason) => {
    const { fetch } = stubSenso({ searchBody: body });
    const senso = new SensoGuidance(KEY, { fetch, ...fast });

    expect(await senso.guidance("dns-deny-limits")).toEqual({ status: "error", topic: "dns-deny-limits", reason });
    expect(senso.status().health).toBe("degraded");
  });

  test("passage text is capped", async () => {
    const { fetch } = stubSenso({ searchBody: { results: [{ content_id: CONTENT, kb_node_id: NODE, chunk_text: "x".repeat(MAX_PASSAGE_CHARS * 3), score: 0.5, rank: 1 }] } });
    const result = await new SensoGuidance(KEY, { fetch, ...fast }).guidance("dns-deny-limits");

    expect(result.status === "ok" && result.passages[0]!.text.length).toBe(MAX_PASSAGE_CHARS);
  });

  test("only the fixed public guidance.md is ever uploaded; topics are frozen", async () => {
    const { calls, fetch } = stubSenso();
    await new SensoGuidance(KEY, { fetch, ...fast }).ensureDocument();

    expect((calls[0]!.body as { text: string }).text).toBe(guidanceText());
    expect(Object.isFrozen(GUIDANCE_QUERIES)).toBe(true);
  });

  test("a non-UUID kb_node_id from Senso is rejected before it is used in a path", async () => {
    const { calls, fetch } = stubSenso({ ingestNodeId: "PRIVATE_NODE_MARKER" });
    const senso = new SensoGuidance(KEY, { fetch, ...fast });

    const result = await senso.guidance("dns-deny-limits");

    expect(result).toEqual({ status: "error", topic: "dns-deny-limits", reason: "response has an invalid kb_node_id" });
    expect(calls.some((call) => call.url.includes("PRIVATE_NODE_MARKER"))).toBe(false);
    expect(JSON.stringify(senso.status())).not.toContain("PRIVATE_NODE_MARKER");
  });

  const HOSTILE_NODE = "deadbeef-dead-4ead-8ead-deaddeadbeef";
  test.each([
    ["http", "GET /org/kb/nodes/:id returned HTTP 500"],
    ["transport", "GET /org/kb/nodes/:id request failed"],
    ["malformed", "GET /org/kb/nodes/:id returned a malformed response"],
  ] as const)("node poll %s failure names the fixed route, never the server-returned id", async (failure, reason) => {
    const { fetch } = stubSenso({ ingestNodeId: HOSTILE_NODE, nodeFailure: failure });
    const senso = new SensoGuidance(KEY, { fetch, ...fast });

    const result = await senso.guidance("dns-deny-limits");

    expect(result).toEqual({ status: "error", topic: "dns-deny-limits", reason });
    expect(JSON.stringify([result, senso.status()])).not.toContain(HOSTILE_NODE);
  });
});
