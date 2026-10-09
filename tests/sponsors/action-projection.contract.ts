// Contract every ActionProjection backend must satisfy. The projection mirrors
// the action journal (cyber26-dni); it must never let a stale or duplicate
// publisher overwrite newer state, and it holds no approval/execution logic.
import { describe, expect, test } from "bun:test";

import { DETAIL_LIMIT, type ActionProjection, type ActionRecord } from "../../src/adapters/sponsors/types.js";
import { FLAGGED, HOSTILE_DOMAIN, uniqueScope } from "./fixtures/observations.js";

export function actionRecord(scope: string, overrides: Partial<ActionRecord> = {}): ActionRecord {
  return {
    digest: `digest-${crypto.randomUUID()}`,
    proposal: {
      action: "dns-deny",
      network_scope: scope,
      resolver_id: "pihole-lab",
      domain: FLAGGED,
      group_id: 2,
      evidence_revision: "evidence:rev-1",
      created_at: Date.parse("2026-10-09T20:02:00.000Z"),
      expires_at: Date.parse("2026-10-09T21:00:00.000Z"),
    },
    status: "proposed",
    approved_by: null,
    verification: null,
    detail: "Proposed from flagged-test-domain evidence",
    ...overrides,
  };
}

export function actionProjectionContract(name: string, makeProjection: () => ActionProjection, enabled = true): void {
  const suite = enabled ? describe : describe.skip;

  suite(`${name} action projection contract`, () => {
    test("unknown digest has no projection", async () => {
      const projection = makeProjection();
      expect(await projection.latest("digest-missing")).toBeNull();
      expect(await projection.history("digest-missing")).toEqual([]);
    });

    test("journal lifecycle is projected revision by revision", async () => {
      const projection = makeProjection();
      const proposed = actionRecord(uniqueScope("life"));
      const approved: ActionRecord = { ...proposed, status: "approved", approved_by: "operator:demo", detail: "Explicit operator approval" };
      const active: ActionRecord = {
        ...approved,
        status: "active",
        detail: "Verified",
        verification: { target: "blocked", benign: "resolved", checked_at: Date.parse("2026-10-09T20:03:00.000Z"), mode: "synthetic" },
      };
      const reverted: ActionRecord = { ...active, status: "reverted", detail: "Rule removed and verified" };

      expect(await projection.publish(proposed, 0)).toEqual({ ok: true, revision: 1 });
      expect(await projection.publish(approved, 1)).toEqual({ ok: true, revision: 2 });
      expect(await projection.publish(active, 2)).toEqual({ ok: true, revision: 3 });
      expect(await projection.publish(reverted, 3)).toEqual({ ok: true, revision: 4 });

      expect(await projection.latest(proposed.digest)).toEqual({ ...reverted, revision: 4 });
      expect((await projection.history(proposed.digest)).map((entry) => [entry.revision, entry.status])).toEqual([
        [1, "proposed"],
        [2, "approved"],
        [3, "active"],
        [4, "reverted"],
      ]);
    });

    test("stale publisher cannot overwrite newer state", async () => {
      const projection = makeProjection();
      const proposed = actionRecord(uniqueScope("stale"));
      await projection.publish(proposed, 0);
      await projection.publish({ ...proposed, status: "approved", approved_by: "operator:demo" }, 1);

      const stale = await projection.publish({ ...proposed, status: "revoked" }, 1);

      expect(stale).toEqual({ ok: false, reason: "stale", current_revision: 2 });
      expect((await projection.latest(proposed.digest))?.status).toBe("approved");
    });

    test("duplicate creation is rejected; skipping ahead is rejected", async () => {
      const projection = makeProjection();
      const proposed = actionRecord(uniqueScope("dup"));
      await projection.publish(proposed, 0);

      expect(await projection.publish(proposed, 0)).toEqual({ ok: false, reason: "stale", current_revision: 1 });
      expect(await projection.publish({ ...proposed, status: "active" }, 5)).toEqual({ ok: false, reason: "stale", current_revision: 1 });
    });

    test("concurrent publishers of the same revision: exactly one wins", async () => {
      const projection = makeProjection();
      const proposed = actionRecord(uniqueScope("race"));
      await projection.publish(proposed, 0);

      const results = await Promise.all(
        Array.from({ length: 8 }, (_, index) =>
          projection.publish({ ...proposed, status: "approved", approved_by: `operator:${index}` }, 1),
        ),
      );

      expect(results.filter((result) => result.ok)).toHaveLength(1);
      expect(await projection.history(proposed.digest)).toHaveLength(2);
    });

    test("inScope returns latest revision per action for that scope only", async () => {
      const projection = makeProjection();
      const scope = uniqueScope("scope");
      const first = actionRecord(scope);
      const second = actionRecord(scope, {
        proposal: { ...actionRecord(scope).proposal, created_at: Date.parse("2026-10-09T20:05:00.000Z") },
      });
      await projection.publish(first, 0);
      await projection.publish({ ...first, status: "approved", approved_by: "operator:demo" }, 1);
      await projection.publish(second, 0);
      await projection.publish(actionRecord(uniqueScope("elsewhere")), 0);

      const listed = await projection.inScope(scope);

      expect(listed.map((entry) => [entry.digest, entry.status, entry.revision])).toEqual([
        [first.digest, "approved", 2],
        [second.digest, "proposed", 1],
      ]);
    });

    test("detail is capped; hostile text stays a value", async () => {
      const projection = makeProjection();
      const scope = uniqueScope("hostile");
      const record = actionRecord(scope, {
        proposal: { ...actionRecord(scope).proposal, domain: HOSTILE_DOMAIN },
        detail: "x".repeat(DETAIL_LIMIT * 3),
      });
      await projection.publish(record, 0);

      const latest = await projection.latest(record.digest);
      expect(latest?.proposal.domain).toBe(HOSTILE_DOMAIN);
      expect(latest?.detail).toHaveLength(DETAIL_LIMIT);
      expect(await projection.latest("{\"$ne\":null}")).toBeNull();
    });
  });
}
