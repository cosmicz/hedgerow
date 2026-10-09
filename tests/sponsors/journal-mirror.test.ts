// The sponsor stores must mirror the action core's durable journal events,
// not the records returned at API boundaries: executing and undoing exist only
// in ledger.history(), with their journal timestamps and verification.
import { afterAll, afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SqliteLedger } from "../../src/actions/ledger.js";
import { ActionService } from "../../src/actions/service.js";
import { MongoClient } from "mongodb";

import { JournalMirror, JournalMirrorError } from "../../src/adapters/sponsors/journal-mirror.js";
import { LocalActionProjection } from "../../src/adapters/sponsors/local/action-projection.js";
import { LocalObservationStore } from "../../src/adapters/sponsors/local/observation-store.js";
import { MongoActionProjection } from "../../src/adapters/sponsors/mongodb/action-projection.js";
import { BENIGN, FLAGGED } from "../../src/adapters/sponsors/scenario.js";
import { SyntheticClock, SyntheticLab } from "../../src/adapters/sponsors/synthetic-lab.js";
import type { ActionProjection } from "../../src/adapters/sponsors/types.js";

const ledgers: SqliteLedger[] = [];
afterEach(() => ledgers.splice(0).forEach((ledger) => ledger.close()));

function setup(projection: ActionProjection = new LocalActionProjection()) {
  const clock = new SyntheticClock(Date.parse("2026-10-09T20:00:00.000Z"));
  const lab = new SyntheticLab({ network_scope: "lab-mirror", clock, probe_client: "192.0.2.53", benign_domain: BENIGN });
  const ledger = new SqliteLedger(join(mkdtempSync(join(tmpdir(), "rg-mirror-")), "journal.sqlite"), () => clock.now());
  ledgers.push(ledger);
  const service = new ActionService({
    ledger,
    adapter: lab.adapter,
    policy: { network_scope: "lab-mirror", resolver_id: "synthetic-resolver", group_id: 2, allowed_domains: [FLAGGED], max_duration_ms: 3_600_000 },
    verify: lab.verify,
    now: () => clock.now(),
    evidence_revision: () => "evidence:mirror",
  });
  const created_at = clock.now();
  const proposal = {
    action: "dns-deny" as const,
    network_scope: "lab-mirror",
    resolver_id: "synthetic-resolver",
    domain: FLAGGED,
    group_id: 2,
    evidence_revision: "evidence:mirror",
    created_at,
    expires_at: created_at + 600_000,
  };
  const store = new LocalObservationStore();
  return { ledger, service, proposal, projection, store, mirror: new JournalMirror(ledger, projection, store) };
}

const live = process.env.RG_SPONSOR_LIVE === "1";
const mongo = new MongoClient(process.env.RG_MONGO_URI ?? "mongodb://127.0.0.1:27717", { serverSelectionTimeoutMS: 2_000 });
const mirrorDb = `router_guard_mirror_test_${crypto.randomUUID().slice(0, 8)}`;
afterAll(async () => {
  if (live) {
    await mongo.db(mirrorDb).dropDatabase();
  }
  await mongo.close();
});

/**
 * Restart transformation: mirror proposed + approved, then a new mirror (and,
 * for MongoDB, a new projection instance over the same durable collection)
 * must project the executing/active events added while it was "down".
 */
function restartContract(name: string, makeProjection: () => ActionProjection, reopen: (projection: ActionProjection) => ActionProjection, enabled: boolean) {
  (enabled ? describe : describe.skip)(`${name} journal mirror restart`, () => {
    test("a recreated mirror resumes from the durable projection; each event exactly once", async () => {
      const run = setup(makeProjection());
      const { digest } = run.service.propose(run.proposal);
      run.service.approve(digest, "operator:mirror");
      await run.mirror.sync(digest);
      const before = (await run.projection.history(digest)).map((entry) => entry.status);

      const reopened = reopen(run.projection);
      const restarted = new JournalMirror(run.ledger, reopened, run.store);
      await run.service.execute(digest);
      const report = await restarted.sync(digest);
      const after = (await reopened.history(digest)).map((entry): [number, string] => [entry.revision, entry.status]);

      expect(before).toEqual(["proposed", "approved"]);
      expect(report.map((event): [number, string] => [event.revision, event.status])).toEqual([
        [1, "proposed"], [2, "approved"], [3, "executing"], [4, "active"],
      ]);
      expect(after).toEqual([[1, "proposed"], [2, "approved"], [3, "executing"], [4, "active"]]);
      expect((await run.store.auditTrail(`journal:${digest}`)).map((event): string => event.kind)).toEqual([
        "proposed", "approved", "executing", "active",
      ]);

      await restarted.sync(digest);
      await new JournalMirror(run.ledger, reopen(reopened), run.store).sync(digest);
      expect(await reopened.history(digest)).toHaveLength(4);
      expect(await run.store.auditTrail(`journal:${digest}`)).toHaveLength(4);
    });
  });
}

restartContract("local", () => new LocalActionProjection(), (projection) => projection, true);
restartContract(
  "mongodb",
  () => new MongoActionProjection(mongo.db(mirrorDb)),
  () => new MongoActionProjection(mongo.db(mirrorDb)),
  live,
);

const JOURNAL: string[] = ["approved", "executing", "active", "undoing", "reverted"];

describe("journal mirror", () => {
  test("mirrors every durable journal event with its timestamp and verification", async () => {
    const { ledger, service, proposal, projection, store, mirror } = setup();
    const { digest } = service.propose(proposal);
    await mirror.sync(digest);
    service.approve(digest, "operator:mirror");
    await mirror.sync(digest);
    await service.execute(digest);
    await mirror.sync(digest);
    await service.undo(digest);
    const mirrored = await mirror.sync(digest);

    const history = ledger.history(digest);
    expect(history.map((event): string => event.status)).toEqual(JOURNAL);
    expect(mirrored.map((event): string => event.status)).toEqual(["proposed", ...JOURNAL]);
    expect(mirrored.slice(1).map((event) => [event.seq, event.at])).toEqual(history.map((event) => [event.seq, event.at]));
    expect(mirrored.map((event) => event.at!)).toEqual([...mirrored.map((event) => event.at!)].sort((a, b) => a - b));
    expect(mirrored.find((event) => event.status === "active")?.verification).toMatchObject({ target: "blocked", benign: "resolved" });
    expect(mirrored.find((event) => event.status === "reverted")?.verification).toMatchObject({ target: "resolved", benign: "resolved" });

    expect((await projection.history(digest)).map((entry): [number, string] => [entry.revision, entry.status])).toEqual(
      ["proposed", ...JOURNAL].map((status, index) => [index + 1, status]),
    );
    expect((await projection.latest(digest))?.approved_by).toBe("operator:mirror");

    const trail = await store.auditTrail(`journal:${digest}`);
    expect(trail.map((event): string => event.kind)).toEqual(["proposed", ...JOURNAL]);
    expect(trail.slice(1).map((event) => Date.parse(event.at))).toEqual(history.map((event) => event.at!));
    // Audit keeps the event's own probe result: undoing carried none, active carried the deny check.
    expect(JSON.parse(trail.find((event) => event.kind === "undoing")!.detail).verification).toBeNull();
    expect(JSON.parse(trail.find((event) => event.kind === "active")!.detail).verification.target).toBe("blocked");
  });

  test("one sync at the end equals syncing after every step; re-sync adds nothing", async () => {
    const stepwise = setup();
    const atEnd = setup();
    for (const run of [stepwise, atEnd]) {
      const { digest } = run.service.propose(run.proposal);
      if (run === stepwise) await run.mirror.sync(digest);
      run.service.approve(digest, "operator:mirror");
      if (run === stepwise) await run.mirror.sync(digest);
      await run.service.execute(digest);
      if (run === stepwise) await run.mirror.sync(digest);
      await run.service.undo(digest);
    }
    const a = await stepwise.mirror.sync(stepwise.ledger.list()[0]!.digest);
    const b = await atEnd.mirror.sync(atEnd.ledger.list()[0]!.digest);
    const again = await atEnd.mirror.sync(atEnd.ledger.list()[0]!.digest);

    expect(a.map((event) => [event.status, event.at, event.revision])).toEqual(b.map((event) => [event.status, event.at, event.revision]));
    expect(again).toHaveLength(b.length);
  });

  test("fails closed when the projection holds a different event at a journal revision", async () => {
    const run = setup();
    const { digest } = run.service.propose(run.proposal);
    await run.mirror.sync(digest);
    const proposed = (await run.projection.latest(digest))!;
    await run.projection.publish({ ...proposed, status: "revoked", detail: "forged" }, 1);
    run.service.approve(digest, "operator:mirror");

    await expect(run.mirror.sync(digest)).rejects.toThrow(JournalMirrorError);
    expect((await run.projection.history(digest)).map((entry): string => entry.status)).toEqual(["proposed", "revoked"]);
    expect((await run.store.auditTrail(`journal:${digest}`)).map((event): string => event.kind)).toEqual(["proposed"]);
  });

  test("fails closed when a publish is refused and the event is not stored", async () => {
    const run = setup();
    const refusing: ActionProjection = {
      backend: "local",
      durable: false,
      publish: async () => ({ ok: false, reason: "stale", current_revision: 0 }),
      latest: async () => null,
      history: async () => [],
      inScope: async () => [],
    };
    const { digest } = run.service.propose(run.proposal);

    await expect(new JournalMirror(run.ledger, refusing, run.store).sync(digest)).rejects.toThrow(JournalMirrorError);
    expect(await run.store.auditTrail(`journal:${digest}`)).toEqual([]);
  });
});
