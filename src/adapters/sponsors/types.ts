// Sponsor-side records for the ClickHouse, MongoDB and Semgrep adapters.
// Observations are the core type from src/domain (cyber26-qce); the sponsor
// stores serialize them but never reinterpret findings.
import type { ActionRecord } from "../../actions/types.js";
import type { Observation, ObservationMode } from "../../domain/observation.js";

export type { ActionRecord, Observation, ObservationMode };

export type LookupOutcome = "answered" | "blocked" | "unknown";

/** One DNS lookup extracted from a dns_query observation. All strings are untrusted data. */
export interface DnsLookupRow {
  readonly observation_id: string;
  readonly observed_at: string;
  readonly network_scope: string;
  readonly source_id: string;
  readonly client: string;
  readonly domain: string;
  readonly outcome: LookupOutcome;
  readonly mode: ObservationMode;
}

export interface EvidenceQuery {
  readonly domain: string;
  readonly network_scope: string;
  /** Inclusive lower bound, ISO-8601 UTC. */
  readonly from: string;
  /** Exclusive upper bound, ISO-8601 UTC. */
  readonly to: string;
}

export type ObservationBackend = "clickhouse" | "local";

/** Aggregate shown to the user as finding evidence and as action verification. */
export interface DomainEvidence {
  readonly domain: string;
  readonly network_scope: string;
  readonly lookups: number;
  readonly clients: readonly string[];
  readonly observation_ids: readonly string[];
  readonly first_seen: string | null;
  readonly last_seen: string | null;
  readonly outcomes: Readonly<Record<LookupOutcome, number>>;
  readonly modes: readonly ObservationMode[];
}

/** Action journal statuses plus the two non-action events the proof records. */
export type AuditKind = ActionRecord["status"] | "finding_evidence" | "security_scan";

export interface AuditEvent {
  readonly id: string;
  readonly at: string;
  readonly subject_id: string;
  readonly kind: AuditKind;
  /** Serialized JSON detail; stored and returned verbatim, never interpreted. */
  readonly detail: string;
}

export interface ObservationStore {
  readonly backend: ObservationBackend;
  /** Stores dns_query observations; replaying the same observation is idempotent. Returns rows accepted. */
  record(observations: readonly Observation[]): Promise<number>;
  domainEvidence(query: EvidenceQuery): Promise<DomainEvidence>;
  appendAudit(event: AuditEvent): Promise<void>;
  auditTrail(subject_id: string): Promise<readonly AuditEvent[]>;
}

// Action records come from the action core (src/actions, cyber26-dni). Its
// SQLite journal is the only execution authority; sponsor backends hold a
// read-side projection of those records for audit and UI.
/** One accepted revision of an ActionRecord as the projection stores it. */
export interface ProjectedAction extends ActionRecord {
  readonly revision: number;
}

export type PublishResult =
  | { readonly ok: true; readonly revision: number }
  | { readonly ok: false; readonly reason: "stale"; readonly current_revision: number };

export type ProjectionBackend = "mongodb" | "local";

/**
 * Read-side projection of the action journal. It never decides approval or
 * execution: publish() only accepts the next revision (compare-and-set on
 * expected_revision), so a stale or duplicate publisher cannot overwrite newer state.
 */
export interface ActionProjection {
  readonly backend: ProjectionBackend;
  /** True when projected records survive process restart. */
  readonly durable: boolean;
  /** expected_revision is the latest revision the publisher saw; 0 for a new digest. */
  publish(record: ActionRecord, expected_revision: number): Promise<PublishResult>;
  latest(digest: string): Promise<ProjectedAction | null>;
  history(digest: string): Promise<readonly ProjectedAction[]>;
  /** Latest revision of every action in a scope, ordered by proposal created_at then digest. */
  inScope(network_scope: string): Promise<readonly ProjectedAction[]>;
}

/** Projection keeps detail for the UI but caps it; raw adapter output is not an audit record. */
export const DETAIL_LIMIT = 500;

export type SponsorHealth = "ok" | "degraded" | "unavailable";

/** Rendered by the demo so every result names the backend that produced it. */
export interface SponsorStatus {
  readonly sponsor: "clickhouse" | "mongodb" | "semgrep";
  readonly health: SponsorHealth;
  readonly serving_backend: string;
  readonly version: string | null;
  readonly detail: string;
  readonly latency_ms: number | null;
}
