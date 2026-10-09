// ClickHouse-backed observation and audit store. Finding evidence and the
// post-action verification view are ClickHouse aggregates over DNS lookups.
// Replays are idempotent: tables are keyed by observation/audit id and every
// read collapses duplicates by id before aggregating.
import { normalizeDomain, toDnsLookupRow } from "../dns-rows.js";
import type {
  AuditEvent,
  AuditKind,
  DomainEvidence,
  EvidenceQuery,
  ObservationMode,
  ObservationStore,
  Observation,
} from "../types.js";
import type { ClickHouseHttp } from "./http.js";

const SCHEMA: readonly string[] = [
  "CREATE DATABASE IF NOT EXISTS router_guard",
  `CREATE TABLE IF NOT EXISTS router_guard.dns_lookups (
    observation_id String,
    observed_at DateTime64(3, 'UTC'),
    network_scope String,
    source_id String,
    client String,
    domain String,
    outcome LowCardinality(String),
    mode LowCardinality(String)
  ) ENGINE = ReplacingMergeTree ORDER BY (network_scope, domain, observation_id)`,
  `CREATE TABLE IF NOT EXISTS router_guard.audit_events (
    id String,
    at DateTime64(3, 'UTC'),
    subject_id String,
    kind LowCardinality(String),
    detail String
  ) ENGINE = ReplacingMergeTree ORDER BY (subject_id, id)`,
];

const INSERT_LOOKUPS = "INSERT INTO router_guard.dns_lookups FORMAT JSONEachRow";
const INSERT_AUDIT = "INSERT INTO router_guard.audit_events FORMAT JSONEachRow";

const EVIDENCE_QUERY = `
SELECT
  toUInt32(count()) AS lookups,
  arraySort(groupUniqArray(lookup_client)) AS clients,
  arraySort(groupArray(lookup_id)) AS observation_ids,
  toUnixTimestamp64Milli(min(lookup_at)) AS first_ms,
  toUnixTimestamp64Milli(max(lookup_at)) AS last_ms,
  toUInt32(countIf(lookup_outcome = 'answered')) AS answered,
  toUInt32(countIf(lookup_outcome = 'blocked')) AS blocked,
  toUInt32(countIf(lookup_outcome = 'unknown')) AS unknown,
  arraySort(groupUniqArray(lookup_mode)) AS modes
FROM (
  -- Distinct aliases: reusing a column name as an alias would shadow it in WHERE.
  SELECT observation_id AS lookup_id, any(observed_at) AS lookup_at, any(client) AS lookup_client,
         any(outcome) AS lookup_outcome, any(mode) AS lookup_mode
  FROM router_guard.dns_lookups
  WHERE network_scope = {scope:String}
    AND domain = {domain:String}
    AND observed_at >= parseDateTime64BestEffort({from:String}, 3, 'UTC')
    AND observed_at < parseDateTime64BestEffort({to:String}, 3, 'UTC')
  GROUP BY observation_id
)`;

const AUDIT_QUERY = `
SELECT id, toUnixTimestamp64Milli(any(at)) AS at_ms, subject_id, any(kind) AS event_kind, any(detail) AS event_detail
FROM router_guard.audit_events
WHERE subject_id = {subject:String}
GROUP BY id, subject_id
ORDER BY at_ms, id`;

interface EvidenceRow {
  lookups: number;
  clients: string[];
  observation_ids: string[];
  first_ms: number;
  last_ms: number;
  answered: number;
  blocked: number;
  unknown: number;
  modes: ObservationMode[];
}

interface AuditRow {
  id: string;
  at_ms: number;
  subject_id: string;
  event_kind: AuditKind;
  event_detail: string;
}

export class ClickHouseObservationStore implements ObservationStore {
  readonly backend = "clickhouse" as const;
  readonly #http: ClickHouseHttp;
  #schema: Promise<void> | null = null;

  constructor(http: ClickHouseHttp) {
    this.#http = http;
  }

  async record(observations: readonly Observation[]): Promise<number> {
    const rows = observations.flatMap((observation) => toDnsLookupRow(observation) ?? []);
    await this.#ready();
    await this.#http.insert(INSERT_LOOKUPS, rows);
    return rows.length;
  }

  async domainEvidence(query: EvidenceQuery): Promise<DomainEvidence> {
    await this.#ready();
    const domain = normalizeDomain(query.domain);
    const [row] = await this.#http.rows<EvidenceRow>(EVIDENCE_QUERY, {
      scope: query.network_scope,
      domain,
      from: query.from,
      to: query.to,
    });
    const empty = !row || row.lookups === 0;
    return {
      domain,
      network_scope: query.network_scope,
      lookups: row?.lookups ?? 0,
      clients: row?.clients ?? [],
      observation_ids: row?.observation_ids ?? [],
      first_seen: empty ? null : new Date(row.first_ms).toISOString(),
      last_seen: empty ? null : new Date(row.last_ms).toISOString(),
      outcomes: { answered: row?.answered ?? 0, blocked: row?.blocked ?? 0, unknown: row?.unknown ?? 0 },
      modes: row?.modes ?? [],
    };
  }

  async appendAudit(event: AuditEvent): Promise<void> {
    await this.#ready();
    await this.#http.insert(INSERT_AUDIT, [event]);
  }

  async auditTrail(subject_id: string): Promise<readonly AuditEvent[]> {
    await this.#ready();
    const rows = await this.#http.rows<AuditRow>(AUDIT_QUERY, { subject: subject_id });
    return rows.map((row) => ({
      id: row.id,
      at: new Date(row.at_ms).toISOString(),
      subject_id: row.subject_id,
      kind: row.event_kind,
      detail: row.event_detail,
    }));
  }

  #ready(): Promise<void> {
    this.#schema ??= this.#createSchema().catch((error: unknown) => {
      this.#schema = null;
      throw error;
    });
    return this.#schema;
  }

  async #createSchema(): Promise<void> {
    for (const statement of SCHEMA) {
      await this.#http.exec(statement);
    }
  }
}
