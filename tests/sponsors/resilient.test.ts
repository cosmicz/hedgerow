// A sponsor failure must leave the evidence/action demo usable and visibly
// degraded, and evidence must never be attributed to a backend that did not
// produce it.
import { describe, expect, test } from "bun:test";

import { LocalActionProjection } from "../../src/adapters/sponsors/local/action-projection.js";
import { LocalObservationStore } from "../../src/adapters/sponsors/local/observation-store.js";
import { ResilientActionProjection, ResilientObservationStore } from "../../src/adapters/sponsors/resilient.js";
import type { ActionProjection, ObservationStore } from "../../src/adapters/sponsors/types.js";
import { actionRecord } from "./action-projection.contract.js";
import { FLAGGED, postActionObservations, preActionObservations, uniqueScope } from "./fixtures/observations.js";

const WINDOW = { from: "2026-10-09T19:00:00.000Z", to: "2026-10-09T21:00:00.000Z" };

/** Behaves like ClickHouse until told to fail. */
class FlakyStore implements ObservationStore {
  readonly backend = "clickhouse" as const;
  readonly inner = new LocalObservationStore();
  failing = false;

  #check(): void {
    if (this.failing) {
      throw new Error("connect ECONNREFUSED 127.0.0.1:18123");
    }
  }
  async record(...args: Parameters<ObservationStore["record"]>) { this.#check(); return this.inner.record(...args); }
  async domainEvidence(...args: Parameters<ObservationStore["domainEvidence"]>) { this.#check(); return this.inner.domainEvidence(...args); }
  async appendAudit(...args: Parameters<ObservationStore["appendAudit"]>) { this.#check(); return this.inner.appendAudit(...args); }
  async auditTrail(...args: Parameters<ObservationStore["auditTrail"]>) { this.#check(); return this.inner.auditTrail(...args); }
}

/** Behaves like the MongoDB projection until told to fail. */
class FlakyProjection implements ActionProjection {
  readonly backend = "mongodb" as const;
  readonly durable = true;
  readonly inner = new LocalActionProjection();
  failing = false;

  async publish(...args: Parameters<ActionProjection["publish"]>) {
    if (this.failing) {
      throw new Error("MongoServerSelectionError");
    }
    return this.inner.publish(...args);
  }
  latest(digest: string) { return this.inner.latest(digest); }
  history(digest: string) { return this.inner.history(digest); }
  inScope(scope: string) { return this.inner.inScope(scope); }
}

describe("resilient observation store", () => {
  test("healthy primary serves evidence and is labelled as such", async () => {
    const primary = new FlakyStore();
    const store = new ResilientObservationStore(primary, "26.10.1");
    const scope = uniqueScope("healthy");
    await store.record(preActionObservations(scope));

    const sourced = await store.sourcedEvidence({ domain: FLAGGED, network_scope: scope, ...WINDOW });

    expect(sourced.backend).toBe("clickhouse");
    expect(sourced.evidence.lookups).toBe(3);
    expect(store.status()).toMatchObject({ health: "ok", serving_backend: "clickhouse" });
  });

  test("primary down from the start: same evidence from local, status degraded", async () => {
    const primary = new FlakyStore();
    primary.failing = true;
    const store = new ResilientObservationStore(primary, null);
    const scope = uniqueScope("down");
    await store.record(preActionObservations(scope));

    const sourced = await store.sourcedEvidence({ domain: FLAGGED, network_scope: scope, ...WINDOW });

    expect(sourced.backend).toBe("local");
    expect(sourced.evidence.lookups).toBe(3);
    expect(store.status()).toMatchObject({ health: "degraded", serving_backend: "local" });
    expect(store.status().detail).toContain("ECONNREFUSED");
  });

  test("a missed write keeps reads local even after the primary recovers", async () => {
    const primary = new FlakyStore();
    const store = new ResilientObservationStore(primary, null);
    const scope = uniqueScope("gap");
    await store.record(preActionObservations(scope));
    primary.failing = true;
    await store.record(postActionObservations(scope));
    primary.failing = false;

    const sourced = await store.sourcedEvidence({ domain: FLAGGED, network_scope: scope, ...WINDOW });

    expect(sourced.backend).toBe("local");
    expect(sourced.evidence.outcomes.blocked).toBe(1);
    expect((await primary.domainEvidence({ domain: FLAGGED, network_scope: scope, ...WINDOW })).outcomes.blocked).toBe(0);
  });
});

describe("resilient action projection", () => {
  test("mongo unavailable at startup: local, not durable, status unavailable", async () => {
    const projection = new ResilientActionProjection(null, null, "connect ECONNREFUSED 127.0.0.1:27717");
    const record = actionRecord(uniqueScope("nomongo"));

    expect(await projection.publish(record, 0)).toEqual({ ok: true, revision: 1 });
    expect(projection.durable).toBe(false);
    expect(projection.status()).toMatchObject({ health: "unavailable", serving_backend: "local" });
  });

  test("mongo failure mid-run: local mirror continues from the accepted revision", async () => {
    const primary = new FlakyProjection();
    const projection = new ResilientActionProjection(primary, "8.0.4");
    const record = actionRecord(uniqueScope("midrun"));
    await projection.publish(record, 0);
    expect(projection.status()).toMatchObject({ health: "ok", serving_backend: "mongodb" });
    const before = await projection.latest(record.digest);

    primary.failing = true;
    const approved = { ...record, status: "approved" as const, approved_by: "operator:demo" };
    const result = await projection.publish(approved, 1);
    const after = await projection.latest(record.digest);

    expect(before?.status).toBe("proposed");
    expect(result).toEqual({ ok: true, revision: 2 });
    expect(after).toMatchObject({ status: "approved", revision: 2 });
    expect(await projection.publish({ ...approved, status: "revoked" }, 1)).toEqual({ ok: false, reason: "stale", current_revision: 2 });
    expect((await projection.history(record.digest)).map((entry) => entry.status)).toEqual(["proposed", "approved"]);
    expect(projection.status()).toMatchObject({ health: "degraded", serving_backend: "local" });
    expect(projection.durable).toBe(false);
  });
});
