import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Database } from "bun:sqlite";
import { ActionService, SqliteLedger, type DnsAdapter, type Rule, type Proposal, type Verification } from "../../src/actions/index";

class FakeDns implements DnsAdapter {
  rule: Rule | null = null;
  creates = 0;
  deletes = 0;
  ambiguous = false;
  async read() { return this.rule && structuredClone(this.rule); }
  async create(rule: Rule) {
    this.creates++;
    this.rule = structuredClone(rule);
    if (this.ambiguous) throw new Error("response lost after write");
  }
  async remove() { this.deletes++; this.rule = null; }
}

const paths: string[] = [];
const ledgers: SqliteLedger[] = [];
afterEach(() => { ledgers.splice(0).forEach(x => x.close()); paths.splice(0).forEach(x => rmSync(x, { recursive: true })); });
function setup() {
  let now = 1_000_000;
  let revision = "evidence-1";
  const path = mkdtempSync(join(tmpdir(), "rg-actions-")); paths.push(path);
  const db = join(path, "actions.sqlite");
  const ledger = new SqliteLedger(db, () => now); ledgers.push(ledger);
  const adapter = new FakeDns();
  let failedVerification = false;
  let probeCount = 0;
  const verify = async (): Promise<Verification> => ({
    target: adapter.rule?.enabled ? "blocked" : "resolved",
    benign: failedVerification && probeCount++ > 0 ? "failed" : "resolved",
    checked_at: now,
    mode: "synthetic",
  });
  const policy = { network_scope: "lab:rg-lab", resolver_id: "pihole-lab", group_id: 1,
    allowed_domains: ["flagged.lab.test"], max_duration_ms: 60_000 };
  const options = { ledger, adapter, verify, policy, now: () => now, evidence_revision: () => revision };
  const service = new ActionService(options);
  const proposal: Proposal = { action: "dns-deny", network_scope: policy.network_scope,
    resolver_id: policy.resolver_id, domain: "flagged.lab.test", group_id: 1,
    evidence_revision: revision, expires_at: now + 30_000, created_at: now };
  return { service, proposal, adapter, ledger, db, options,
    tick: (n: number) => { now += n; }, stale: () => { revision = "evidence-2"; },
    failVerification: () => { failedVerification = true; } };
}

describe("approved DNS action lifecycle", () => {
  test("old journal migration preserves unknown historical timestamps", () => {
    const path = mkdtempSync(join(tmpdir(),"rg-old-journal-")); paths.push(path);
    const file = join(path,"actions.sqlite"); const db = new Database(file,{create:true});
    db.exec("CREATE TABLE action_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,digest TEXT,status TEXT,detail TEXT)");
    db.query("INSERT INTO action_events(digest,status,detail) VALUES (?,?,?)").run("historical","active","old event");
    db.close();
    const ledger = new SqliteLedger(file,()=>123); ledgers.push(ledger);
    expect(ledger.history("historical")).toEqual([{seq:1,digest:"historical",status:"active",detail:"old event",at:null,verification:null}]);
  });
  test("undo preserves timestamped apply verification in durable event history", async () => {
    const s = setup(); const p = s.service.propose(s.proposal); s.service.approve(p.digest,"operator");
    await s.service.execute(p.digest);
    s.tick(100);
    await s.service.undo(p.digest);
    const events = s.ledger.history(p.digest);
    expect(events.find(x=>x.status === "active")?.verification?.target).toBe("blocked");
    expect(events.find(x=>x.status === "active")?.at).toBe(1_000_000);
    expect(events.find(x=>x.status === "reverted")?.at).toBe(1_000_100);
    expect(events.find(x=>x.status === "reverted")?.verification?.target).toBe("resolved");
    expect(s.ledger.get(p.digest).verification?.target).toBe("resolved");
    expect(events.map(x=>x.status)).toEqual(["approved","executing","active","undoing","reverted"]);
    const t = setup(); const q = t.service.propose(t.proposal); t.service.approve(q.digest,"operator");
    await t.service.execute(q.digest);
    t.adapter.rule!.comment = "external edit";
    await t.service.undo(q.digest);
    expect(t.ledger.get(q.digest).status).toBe("conflict");
    expect(t.ledger.get(q.digest).verification?.target).toBe("blocked");
  });
  test("absent -> approved deny -> independently verified -> undo restores; benign survives", async () => {
    const s = setup();
    const p = s.service.propose(s.proposal);
    expect(s.adapter.rule).toBeNull();
    s.service.approve(p.digest, "operator");
    const applied = await s.service.execute(p.digest);
    expect(applied.status).toBe("active");
    expect(applied.verification?.target).toBe("blocked");
    expect(applied.verification?.benign).toBe("resolved");
    expect(s.adapter.rule?.domain).toBe("flagged.lab.test");
    expect((await s.service.undo(p.digest)).status).toBe("reverted");
    expect(s.adapter.rule).toBeNull();
    expect(s.adapter.deletes).toBe(1);
  });
  test("unapproved, modified, revoked, expired and stale evidence cannot mutate", async () => {
    const s = setup(); const p = s.service.propose(s.proposal);
    await expect(s.service.execute(p.digest)).rejects.toThrow();
    s.service.approve(p.digest, "operator"); s.service.revoke(p.digest);
    await expect(s.service.execute(p.digest)).rejects.toThrow();
    expect(() => s.service.propose({ ...s.proposal, domain: "benign.lab.test" })).toThrow();
    expect(() => s.service.propose({ ...s.proposal, network_scope: "production" })).toThrow();
    expect(() => s.service.propose({ ...s.proposal, group_id: 0 })).toThrow();
    const fresh = s.service.propose({ ...s.proposal, expires_at: s.proposal.expires_at + 1 });
    s.service.approve(fresh.digest, "operator"); s.stale();
    await expect(s.service.execute(fresh.digest)).rejects.toThrow();
    s.tick(60_000);
    expect(() => s.service.approve(fresh.digest, "operator")).toThrow();
    expect(s.adapter.creates).toBe(0);
  });
  test("duplicate concurrent execution produces one rule", async () => {
    const s = setup(); const p = s.service.propose(s.proposal); s.service.approve(p.digest, "operator");
    await Promise.allSettled([s.service.execute(p.digest), s.service.execute(p.digest)]);
    expect(s.adapter.creates).toBe(1);
    expect((await s.service.execute(p.digest)).status).toBe("active");
    expect(s.adapter.creates).toBe(1);
  });
  test("journal tampering invalidates approval and interrupted execution is never replayed", async () => {
    const s = setup(); const p = s.service.propose(s.proposal); s.service.approve(p.digest, "operator");
    const db = new Database(s.db);
    db.query("UPDATE actions SET proposal=? WHERE digest=?").run(JSON.stringify({...s.proposal, expires_at: s.proposal.expires_at + 10}), p.digest);
    db.close();
    await expect(s.service.execute(p.digest)).rejects.toThrow();
    expect(s.adapter.creates).toBe(0);
    const t = setup(); const q = t.service.propose(t.proposal); t.service.approve(q.digest, "operator");
    t.ledger.transition(q.digest, ["approved"], "executing");
    await t.service.reconcile();
    expect(t.ledger.get(q.digest).status).toBe("executing");
    await t.service.reconcile(true);
    expect(t.ledger.get(q.digest).status).toBe("ambiguous");
    await t.service.execute(q.digest);
    expect(t.adapter.creates).toBe(0);
  });
  test("two approved proposals cannot concurrently mutate the same resolver domain", async () => {
    const s = setup();
    const p = s.service.propose(s.proposal);
    const q = s.service.propose({...s.proposal, expires_at: s.proposal.expires_at + 1});
    s.service.approve(p.digest, "operator"); s.service.approve(q.digest, "operator");
    await Promise.allSettled([s.service.execute(p.digest), s.service.execute(q.digest)]);
    expect(s.adapter.creates).toBe(1);
    expect(s.ledger.list().filter(x => x.status === "active")).toHaveLength(1);
  });
  test("preexisting and externally modified rules are preserved", async () => {
    const s = setup(); const p = s.service.propose(s.proposal); s.service.approve(p.digest, "operator");
    s.adapter.rule = { domain: s.proposal.domain, groups: [0], enabled: true, comment: "operator rule" };
    expect((await s.service.execute(p.digest)).status).toBe("conflict");
    expect(s.adapter.creates).toBe(0);
    expect((await s.service.undo(p.digest)).status).toBe("conflict");
    expect(s.adapter.deletes).toBe(0);
    const t = setup(); const q = t.service.propose(t.proposal); t.service.approve(q.digest, "operator");
    await t.service.execute(q.digest); t.adapter.rule!.groups = [0, 1];
    expect((await t.service.undo(q.digest)).status).toBe("conflict");
    expect(t.adapter.deletes).toBe(0);
  });
  test("lost mutation response is ambiguous; no retry; owned rule can be undone", async () => {
    const s = setup(); s.adapter.ambiguous = true;
    const p = s.service.propose(s.proposal); s.service.approve(p.digest, "operator");
    expect((await s.service.execute(p.digest)).status).toBe("ambiguous");
    await s.service.execute(p.digest);
    expect(s.adapter.creates).toBe(1);
    expect((await s.service.undo(p.digest)).status).toBe("reverted");
    expect(s.adapter.rule).toBeNull();
  });
  test("expiry after restart restores owned rule", async () => {
    const s = setup(); const p = s.service.propose(s.proposal); s.service.approve(p.digest, "operator");
    await s.service.execute(p.digest); s.tick(31_000);
    const ledger = new SqliteLedger(s.db); ledgers.push(ledger);
    const restarted = new ActionService({ ...s.options, ledger });
    await restarted.reconcile();
    expect(ledger.get(p.digest).status).toBe("reverted");
    expect(s.adapter.rule).toBeNull();
  });
  test("unhealthy baseline prevents mutation and expiry during verification rolls back", async () => {
    const s = setup();
    const unhealthy = new ActionService({ ...s.options, verify: async () => ({target: "failed", benign: "resolved", checked_at: 1_000_000, mode: "synthetic"}) });
    const p = unhealthy.propose(s.proposal); unhealthy.approve(p.digest, "operator");
    expect((await unhealthy.execute(p.digest)).status).toBe("failed");
    expect(s.adapter.creates).toBe(0);
    const t = setup(); let calls = 0;
    const delayed = new ActionService({ ...t.options, verify: async (p) => {
      if (++calls === 2) t.tick(40_000);
      return t.options.verify();
    } });
    const q = delayed.propose(t.proposal); delayed.approve(q.digest, "operator");
    expect((await delayed.execute(q.digest)).status).toBe("reverted");
    expect(t.adapter.creates).toBe(1); expect(t.adapter.rule).toBeNull();
  });
  test("failed independent verification rolls back and reports degraded restoration", async () => {
    const s = setup(); const p = s.service.propose(s.proposal); s.service.approve(p.digest, "operator");
    s.failVerification();
    const result = await s.service.execute(p.digest);
    expect(result.status).toBe("rollback-unverified");
    expect(s.adapter.rule).toBeNull();
    expect(s.adapter.creates).toBe(1);
    expect(s.adapter.deletes).toBe(1);
  });
});
