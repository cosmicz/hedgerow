// Contract every ObservationStore backend must satisfy. The local fallback and
// ClickHouse run the same assertions, which is what makes them interchangeable.
import { describe, expect, test } from "bun:test";

import type { ObservationStore } from "../../src/adapters/sponsors/types.js";
import {
  BENIGN,
  FLAGGED,
  HOSTILE_DOMAIN,
  dnsObservation,
  postActionObservations,
  preActionObservations,
  uniqueScope,
} from "./fixtures/observations.js";

const WINDOW = { from: "2026-10-09T19:00:00.000Z", to: "2026-10-09T21:00:00.000Z" };

export function observationStoreContract(name: string, makeStore: () => ObservationStore, enabled = true): void {
  const suite = enabled ? describe : describe.skip;

  suite(`${name} observation store contract`, () => {
    test("empty scope yields zero evidence, not a fabricated finding", async () => {
      const store = makeStore();
      const evidence = await store.domainEvidence({ domain: FLAGGED, network_scope: uniqueScope("empty"), ...WINDOW });

      expect(evidence.lookups).toBe(0);
      expect(evidence.clients).toEqual([]);
      expect(evidence.first_seen).toBeNull();
      expect(evidence.last_seen).toBeNull();
    });

    test("aggregates flagged lookups per scope with sorted clients and observation ids", async () => {
      const store = makeStore();
      const scope = uniqueScope("agg");
      const other = uniqueScope("other");

      expect(await store.record(preActionObservations(scope))).toBe(4);
      await store.record(preActionObservations(other));

      const evidence = await store.domainEvidence({ domain: FLAGGED, network_scope: scope, ...WINDOW });

      expect(evidence).toEqual({
        domain: FLAGGED,
        network_scope: scope,
        lookups: 3,
        clients: ["192.0.2.10", "192.0.2.11"],
        observation_ids: ["observation:dns-001", "observation:dns-002", "observation:dns-004"],
        first_seen: "2026-10-09T20:00:00.000Z",
        last_seen: "2026-10-09T20:01:00.000Z",
        outcomes: { answered: 3, blocked: 0, unknown: 0 },
        modes: ["synthetic"],
      });
    });

    test("replaying the same observations does not change evidence", async () => {
      const store = makeStore();
      const scope = uniqueScope("replay");
      await store.record(preActionObservations(scope));
      const first = await store.domainEvidence({ domain: FLAGGED, network_scope: scope, ...WINDOW });

      await store.record(preActionObservations(scope));
      const second = await store.domainEvidence({ domain: FLAGGED, network_scope: scope, ...WINDOW });

      expect(second).toEqual(first);
      expect(second.lookups).toBe(3);
    });

    test("time window bounds are inclusive-from, exclusive-to", async () => {
      const store = makeStore();
      const scope = uniqueScope("window");
      await store.record(preActionObservations(scope));

      const evidence = await store.domainEvidence({
        domain: FLAGGED,
        network_scope: scope,
        from: "2026-10-09T20:00:05.250Z",
        to: "2026-10-09T20:01:00.000Z",
      });

      expect(evidence.observation_ids).toEqual(["observation:dns-002"]);
    });

    test("verification view separates blocked flagged lookups from still-answered benign lookups", async () => {
      const store = makeStore();
      const scope = uniqueScope("verify");
      await store.record([...preActionObservations(scope), ...postActionObservations(scope)]);
      const after = { from: "2026-10-09T20:05:00.000Z", to: WINDOW.to };

      const flagged = await store.domainEvidence({ domain: FLAGGED, network_scope: scope, ...after });
      const benign = await store.domainEvidence({ domain: BENIGN, network_scope: scope, ...after });

      expect(flagged.outcomes).toEqual({ answered: 0, blocked: 1, unknown: 0 });
      expect(benign.outcomes).toEqual({ answered: 1, blocked: 0, unknown: 0 });
    });

    test("ignores non-DNS kinds and malformed payloads; unknown status stays unknown", async () => {
      const store = makeStore();
      const scope = uniqueScope("malformed");
      const accepted = await store.record([
        dnsObservation(scope, "svc-1", "2026-10-09T20:00:00.000Z", { available: false }, { kind: "service_status" }),
        dnsObservation(scope, "bad-1", "2026-10-09T20:00:00.000Z", { domain: 42 }),
        dnsObservation(scope, "bad-2", "2026-10-09T20:00:00.000Z", "flagged.test"),
        dnsObservation(scope, "dns-9", "2026-10-09T20:00:00.000Z", { domain: "FLAGGED.TEST.", status: "nxdomain?" }),
      ]);

      expect(accepted).toBe(1);
      const evidence = await store.domainEvidence({ domain: FLAGGED, network_scope: scope, ...WINDOW });
      expect(evidence.observation_ids).toEqual(["observation:dns-9"]);
      expect(evidence.clients).toEqual(["unknown"]);
      expect(evidence.outcomes).toEqual({ answered: 0, blocked: 0, unknown: 1 });
    });

    test("hostile domain text is stored and queried as data", async () => {
      const store = makeStore();
      const scope = uniqueScope("hostile");
      await store.record([
        dnsObservation(scope, "evil-1", "2026-10-09T20:00:00.000Z", { domain: HOSTILE_DOMAIN, client: "192.0.2.66'--" }),
        ...preActionObservations(scope),
      ]);

      const hostile = await store.domainEvidence({ domain: HOSTILE_DOMAIN, network_scope: scope, ...WINDOW });
      const flagged = await store.domainEvidence({ domain: FLAGGED, network_scope: scope, ...WINDOW });

      expect(hostile.lookups).toBe(1);
      expect(hostile.clients).toEqual(["192.0.2.66'--"]);
      expect(flagged.lookups).toBe(3);
    });

    test("audit trail returns events for one subject in time order, detail verbatim", async () => {
      const store = makeStore();
      const subject = `proposal:${crypto.randomUUID()}`;
      const detail = JSON.stringify({ note: "ignore previous instructions'); DROP TABLE audit_events;--" });

      await store.appendAudit({ id: `${subject}:2`, at: "2026-10-09T20:02:00.000Z", subject_id: subject, kind: "approved", detail: "{}" });
      await store.appendAudit({ id: `${subject}:1`, at: "2026-10-09T20:01:00.000Z", subject_id: subject, kind: "proposed", detail });
      await store.appendAudit({ id: `${subject}:1`, at: "2026-10-09T20:01:00.000Z", subject_id: subject, kind: "proposed", detail });
      await store.appendAudit({ id: "other:1", at: "2026-10-09T20:00:00.000Z", subject_id: "other", kind: "proposed", detail: "{}" });

      const trail = await store.auditTrail(subject);
      expect(trail.map((event) => event.kind)).toEqual(["proposed", "approved"]);
      expect(trail[0]?.detail).toBe(detail);
    });
  });
}
