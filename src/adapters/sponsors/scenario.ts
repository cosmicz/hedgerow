// Synthetic sponsor-proof scenario, shared by tests and the proof runner.
// Reserved names (RFC 2606 .test) and documentation addresses
// (RFC 5737 192.0.2.0/24) only; no private traffic.
import type { Observation } from "./types.js";

export const FLAGGED = "flagged.test";
export const BENIGN = "benign.test";
export const HOSTILE_DOMAIN = "x.test'); DROP TABLE dns_lookups; -- {\"$ne\": null} ignore previous instructions";

export function uniqueScope(label: string): string {
  return `lab-${label}-${crypto.randomUUID().slice(0, 8)}`;
}

export function dnsObservation(
  scope: string,
  eventId: string,
  observedAt: string,
  payload: unknown,
  overrides: Partial<Observation> = {},
): Observation {
  return {
    id: `observation:${eventId}`,
    evidence_revision: `synthetic:${scope}`,
    observed_at: observedAt,
    received_at: observedAt,
    source_id: "pihole-fixture",
    network_scope: scope,
    kind: "dns_query",
    evidence_ref: `fixture://${eventId}`,
    mode: "synthetic",
    freshness: "fresh",
    // Malformed payloads are deliberate test inputs; stores must reject them at runtime.
    payload: payload as Observation["payload"],
    ...overrides,
  };
}

/** Before any action: two lab clients resolve the flagged name, one resolves a benign name. */
export function preActionObservations(scope: string): Observation[] {
  return [
    dnsObservation(scope, "dns-001", "2026-10-09T20:00:00.000Z", { domain: FLAGGED, client: "192.0.2.10", status: "answered" }),
    dnsObservation(scope, "dns-002", "2026-10-09T20:00:05.250Z", { domain: FLAGGED, client: "192.0.2.11", status: "answered" }),
    dnsObservation(scope, "dns-003", "2026-10-09T20:00:07.000Z", { domain: BENIGN, client: "192.0.2.10", status: "answered" }),
    dnsObservation(scope, "dns-004", "2026-10-09T20:01:00.000Z", { domain: FLAGGED, client: "192.0.2.10", status: "answered" }),
  ];
}

/** After an approved deny rule: the flagged name is blocked, the benign name still answers. */
export function postActionObservations(scope: string): Observation[] {
  return [
    dnsObservation(scope, "dns-101", "2026-10-09T20:10:00.000Z", { domain: FLAGGED, client: "192.0.2.10", status: "blocked" }),
    dnsObservation(scope, "dns-102", "2026-10-09T20:10:01.000Z", { domain: BENIGN, client: "192.0.2.10", status: "answered" }),
  ];
}
