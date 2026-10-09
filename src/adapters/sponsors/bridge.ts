// UI-facing sponsor bridge. One object the server holds for the session.
//
// Inputs are the product's real data: core Observations (src/domain) and the
// action core's durable journal (SqliteLedger, through JournalSource). Outputs
// are what the UI renders, each labelled with the backend that produced it.
//
// - ClickHouse: DNS observations and audit events; evidence queries.
// - MongoDB: read-side projection of the action journal.
// - Either sponsor down or unconfigured: in-process fallback, visibly not ok.
//
// The bridge never throws because a sponsor is unavailable, and it never grants
// or withholds action authority. A journal/projection mismatch is reported,
// not hidden. Sponsor eligibility is a separate, human-confirmed fact; MongoDB
// is reported "unconfirmed" until cyber26-5iz records otherwise.
import { MongoClient } from "mongodb";

import type { Observation } from "../../domain/observation.js";
import { ClickHouseHttp } from "./clickhouse/http.js";
import { ClickHouseObservationStore } from "./clickhouse/observation-store.js";
import { checkClickHouseEndpoint, checkMongoEndpoint } from "./endpoints.js";
import { JournalMirror, type JournalSource, type MirroredEvent } from "./journal-mirror.js";
import { MongoActionProjection } from "./mongodb/action-projection.js";
import { ResilientActionProjection, ResilientObservationStore, type SourcedEvidence } from "./resilient.js";
import type { SecurityScanEvidence } from "./semgrep/scan.js";
import type { AuditEvent, EvidenceQuery, ProjectedAction, SponsorStatus } from "./types.js";

export interface SponsorBridgeConfig {
  /** Omit to run without ClickHouse (reported unavailable: not configured). */
  readonly clickhouse?: { readonly url: string; readonly timeoutMs?: number };
  /** Omit to run without MongoDB (reported unavailable: not configured). */
  readonly mongodb?: { readonly uri: string; readonly database?: string; readonly serverSelectionTimeoutMs?: number };
}

/**
 * directConnection: true stops the driver from discovering and connecting to
 * replica-set members other than the validated loopback host.
 */
export interface MongoBoundaryOptions {
  readonly serverSelectionTimeoutMS: number;
  readonly directConnection: true;
}

/** Client factories; tests inject stubs to prove that invalid endpoints are never contacted. */
export interface SponsorBridgeDeps {
  readonly fetch?: typeof fetch;
  readonly mongoClient?: (uri: string, options: MongoBoundaryOptions) => MongoClient;
}

export type SponsorEligibility = "organizer-listed" | "unconfirmed";

export interface SponsorReport {
  readonly generated_at: string;
  readonly sponsors: readonly SponsorStatus[];
  /** Organizer sponsor-card status, recorded by people, not inferred from health. */
  readonly eligibility: Readonly<Record<"clickhouse" | "mongodb" | "semgrep", SponsorEligibility>>;
  readonly last_mirror_error: string | null;
  readonly security_scan: SecurityScanEvidence | null;
}

export interface RecordResult {
  readonly accepted: number;
  /** Non-DNS kinds and malformed DNS payloads are not stored. */
  readonly ignored: number;
  readonly backend: "clickhouse" | "local";
}

export interface MirrorReport {
  readonly ok: boolean;
  readonly digest: string;
  readonly events: readonly MirroredEvent[];
  readonly backend: "mongodb" | "local";
  readonly error: string | null;
}

export interface Sourced<T> {
  readonly value: T;
  readonly backend: string;
}

export const ELIGIBILITY: SponsorReport["eligibility"] = {
  clickhouse: "organizer-listed",
  semgrep: "organizer-listed",
  mongodb: "unconfirmed",
};

export class SponsorBridge {
  readonly #store: ResilientObservationStore;
  readonly #projection: ResilientActionProjection;
  readonly #close: () => Promise<void>;
  #lastMirrorError: string | null = null;
  #securityScan: SecurityScanEvidence | null = null;

  constructor(store: ResilientObservationStore, projection: ResilientActionProjection, close: () => Promise<void> = async () => {}) {
    this.#store = store;
    this.#projection = projection;
    this.#close = close;
  }

  /**
   * Connects to whichever sponsors are configured. Endpoints must be loopback
   * (see endpoints.ts); invalid ones are never contacted. Unreachable or
   * invalid sponsors fall back locally and are reported with the reason.
   */
  static async open(config: SponsorBridgeConfig, deps: SponsorBridgeDeps = {}): Promise<SponsorBridge> {
    const store = await openClickHouse(config.clickhouse, deps);
    const { projection, client } = await openMongo(config.mongodb, deps);
    return new SponsorBridge(store, projection, async () => {
      await client?.close();
    });
  }

  async recordObservations(observations: readonly Observation[]): Promise<RecordResult> {
    const accepted = await this.#store.record(observations);
    return { accepted, ignored: observations.length - accepted, backend: this.#store.backend };
  }

  evidence(query: EvidenceQuery): Promise<SourcedEvidence> {
    return this.#store.sourcedEvidence(query);
  }

  /** Mirrors the journal for one action. Call after each ActionService operation, or on startup. */
  async mirrorJournal(journal: JournalSource, digest: string): Promise<MirrorReport> {
    try {
      const events = await new JournalMirror(journal, this.#projection, this.#store).sync(digest);
      return { ok: true, digest, events, backend: this.#projection.backend, error: null };
    } catch (error) {
      this.#lastMirrorError = `${digest}: ${(error as Error).message}`.slice(0, 300);
      return { ok: false, digest, events: [], backend: this.#projection.backend, error: this.#lastMirrorError };
    }
  }

  async actions(network_scope: string): Promise<Sourced<readonly ProjectedAction[]>> {
    const value = await this.#projection.inScope(network_scope);
    return { value, backend: this.#projection.backend };
  }

  async actionHistory(digest: string): Promise<Sourced<readonly ProjectedAction[]>> {
    const value = await this.#projection.history(digest);
    return { value, backend: this.#projection.backend };
  }

  async journalAudit(digest: string): Promise<Sourced<readonly AuditEvent[]>> {
    const value = await this.#store.auditTrail(`journal:${digest}`);
    return { value, backend: this.#store.backend };
  }

  /** Records a Semgrep result produced elsewhere (e.g. the proof run) so the UI can show it with its revision. */
  async recordSecurityScan(scan: SecurityScanEvidence): Promise<void> {
    this.#securityScan = scan;
    await this.#store.appendAudit({
      id: `security_scan:${scan.revision ?? "unknown"}:${scan.scanned_at}`,
      at: scan.scanned_at,
      subject_id: "security_scan",
      kind: "security_scan",
      detail: JSON.stringify({ status: scan.status, revision: scan.revision, dirty: scan.worktree_dirty, findings: scan.findings.length }),
    });
  }

  status(): SponsorReport {
    return {
      generated_at: new Date().toISOString(),
      sponsors: [this.#store.status(), this.#projection.status()],
      eligibility: ELIGIBILITY,
      last_mirror_error: this.#lastMirrorError,
      security_scan: this.#securityScan,
    };
  }

  close(): Promise<void> {
    return this.#close();
  }
}

async function openClickHouse(config: SponsorBridgeConfig["clickhouse"], deps: SponsorBridgeDeps): Promise<ResilientObservationStore> {
  if (!config) {
    return new ResilientObservationStore(null, null, "not configured");
  }
  const endpoint = checkClickHouseEndpoint(config.url);
  if (!endpoint.ok) {
    return new ResilientObservationStore(null, null, endpoint.reason);
  }
  const http = new ClickHouseHttp({ url: endpoint.url, timeoutMs: config.timeoutMs ?? 2_000, fetch: deps.fetch });
  try {
    const version = await http.version();
    return new ResilientObservationStore(new ClickHouseObservationStore(http), version);
  } catch (error) {
    return new ResilientObservationStore(null, null, (error as Error).message.slice(0, 200));
  }
}

async function openMongo(
  config: SponsorBridgeConfig["mongodb"],
  deps: SponsorBridgeDeps,
): Promise<{ projection: ResilientActionProjection; client: MongoClient | null }> {
  if (!config) {
    return { projection: new ResilientActionProjection(null, null, "not configured"), client: null };
  }
  const endpoint = checkMongoEndpoint(config.uri);
  if (!endpoint.ok) {
    return { projection: new ResilientActionProjection(null, null, endpoint.reason), client: null };
  }
  const makeClient = deps.mongoClient ?? ((uri, options) => new MongoClient(uri, options));
  let client: MongoClient | null = null;
  try {
    client = makeClient(endpoint.url, { serverSelectionTimeoutMS: config.serverSelectionTimeoutMs ?? 1_500, directConnection: true });
    const info = await client.db("admin").command({ buildInfo: 1 });
    const projection = new MongoActionProjection(client.db(config.database ?? "router_guard"));
    return { projection: new ResilientActionProjection(projection, String(info.version)), client };
  } catch (error) {
    await client?.close();
    return { projection: new ResilientActionProjection(null, null, (error as Error).message.slice(0, 200)), client: null };
  }
}
