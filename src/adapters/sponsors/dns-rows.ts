// Extraction shared by every ObservationStore backend, so ClickHouse and the
// local fallback agree on which observations count and how names compare.
import type { DnsLookupRow, LookupOutcome, Observation } from "./types.js";

/** Lowercase and drop one trailing root dot; DNS names compare case-insensitively. */
export function normalizeDomain(domain: string): string {
  const lower = domain.toLowerCase();
  return lower.endsWith(".") ? lower.slice(0, -1) : lower;
}

/** Returns null for non-DNS kinds or payloads without a string domain. */
export function toDnsLookupRow(observation: Observation): DnsLookupRow | null {
  if (observation.kind !== "dns_query" || !isRecord(observation.payload)) {
    return null;
  }
  const { domain, client, status } = observation.payload;
  if (typeof domain !== "string" || domain.length === 0) {
    return null;
  }
  return {
    observation_id: observation.id,
    observed_at: new Date(observation.observed_at).toISOString(),
    network_scope: observation.network_scope,
    source_id: observation.source_id,
    client: typeof client === "string" && client.length > 0 ? client : "unknown",
    domain: normalizeDomain(domain),
    outcome: toOutcome(status),
    mode: observation.mode,
  };
}

function toOutcome(status: unknown): LookupOutcome {
  return status === "answered" || status === "blocked" ? status : "unknown";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
