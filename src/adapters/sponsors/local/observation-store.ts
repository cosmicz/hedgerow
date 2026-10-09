// In-process fallback for the ClickHouse observation store. Same contract,
// no persistence; used when ClickHouse is unreachable and as the parity oracle.
import { normalizeDomain, toDnsLookupRow } from "../dns-rows.js";
import type {
  AuditEvent,
  DnsLookupRow,
  DomainEvidence,
  EvidenceQuery,
  LookupOutcome,
  ObservationMode,
  ObservationStore,
  Observation,
} from "../types.js";

export class LocalObservationStore implements ObservationStore {
  readonly backend = "local" as const;
  readonly #rows = new Map<string, DnsLookupRow>();
  readonly #audit = new Map<string, AuditEvent>();

  async record(observations: readonly Observation[]): Promise<number> {
    let accepted = 0;
    for (const observation of observations) {
      const row = toDnsLookupRow(observation);
      if (row) {
        // Same identity as the ClickHouse sort key, so replays dedupe identically.
        this.#rows.set(JSON.stringify([row.network_scope, row.domain, row.observation_id]), row);
        accepted += 1;
      }
    }
    return accepted;
  }

  async domainEvidence(query: EvidenceQuery): Promise<DomainEvidence> {
    const domain = normalizeDomain(query.domain);
    const from = Date.parse(query.from);
    const to = Date.parse(query.to);
    const rows = [...this.#rows.values()].filter((row) => {
      const at = Date.parse(row.observed_at);
      return row.domain === domain && row.network_scope === query.network_scope && at >= from && at < to;
    });
    const times = rows.map((row) => row.observed_at).sort();
    const outcomes: Record<LookupOutcome, number> = { answered: 0, blocked: 0, unknown: 0 };
    for (const row of rows) {
      outcomes[row.outcome] += 1;
    }
    return {
      domain,
      network_scope: query.network_scope,
      lookups: rows.length,
      clients: sortedUnique(rows.map((row) => row.client)),
      observation_ids: sortedUnique(rows.map((row) => row.observation_id)),
      first_seen: times[0] ?? null,
      last_seen: times.at(-1) ?? null,
      outcomes,
      modes: sortedUnique(rows.map((row) => row.mode)) as ObservationMode[],
    };
  }

  async appendAudit(event: AuditEvent): Promise<void> {
    if (!this.#audit.has(event.id)) {
      this.#audit.set(event.id, event);
    }
  }

  async auditTrail(subject_id: string): Promise<readonly AuditEvent[]> {
    return [...this.#audit.values()]
      .filter((event) => event.subject_id === subject_id)
      .sort((a, b) => a.at.localeCompare(b.at) || a.id.localeCompare(b.id));
  }
}

function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort();
}
