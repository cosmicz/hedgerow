import { createHash } from "node:crypto";
import { SqliteLedger } from "./ledger";
import type { ActionRecord, DnsAdapter, Policy, Proposal, Rule, Verification } from "./types";

interface Options {
  ledger: SqliteLedger;
  adapter: DnsAdapter;
  policy: Policy;
  verify: (proposal: Proposal, expected: "blocked" | "resolved") => Promise<Verification>;
  now: () => number;
  evidence_revision: () => string;
}

// Explicit fields make approval independent of object property insertion order.
export function proposalDigest(p: Proposal): string {
  return createHash("sha256").update(JSON.stringify([
    p.action, p.network_scope, p.resolver_id, p.domain, p.group_id,
    p.evidence_revision, p.created_at, p.expires_at,
  ])).digest("hex");
}
function ownedRule(record: ActionRecord): Rule {
  return { domain: record.proposal.domain, groups: [record.proposal.group_id],
    enabled: true, comment: `router-guard:${record.digest}` };
}
function matches(actual: Rule, expected: Rule): boolean {
  return actual.domain === expected.domain && actual.enabled === expected.enabled &&
    actual.comment === expected.comment && actual.groups.length === expected.groups.length &&
    [...actual.groups].sort().join(",") === [...expected.groups].sort().join(",");
}

export class ActionService {
  constructor(private readonly o: Options) {}
  private validate(p: Proposal, execution = true) {
    const { policy, now } = this.o;
    if (p.action !== "dns-deny" || p.network_scope !== policy.network_scope ||
      p.resolver_id !== policy.resolver_id || p.group_id !== policy.group_id ||
      !Number.isSafeInteger(p.group_id) || p.group_id < 1 ||
      !policy.allowed_domains.includes(p.domain) ||
      !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]+$/.test(p.domain)) {
      throw new Error("Proposal outside configured exact lab scope");
    }
    if (!Number.isSafeInteger(p.created_at) || !Number.isSafeInteger(p.expires_at) ||
      p.created_at > now() || p.expires_at <= p.created_at ||
      p.expires_at - p.created_at > policy.max_duration_ms ||
      typeof p.evidence_revision !== "string" || !p.evidence_revision) throw new Error("Invalid proposal bounds");
    if (execution && (p.expires_at <= now() || p.evidence_revision !== this.o.evidence_revision())) {
      throw new Error("Expired proposal or changed evidence");
    }
  }
  propose(proposal: Proposal) {
    this.validate(proposal);
    return this.o.ledger.put(proposalDigest(proposal), structuredClone(proposal));
  }
  approve(digest: string, operator: string) {
    const record = this.o.ledger.get(digest); this.validate(record.proposal);
    if (!operator.trim() || operator.length > 128 || proposalDigest(record.proposal) !== digest) throw new Error("Invalid approval");
    if (!this.o.ledger.transition(digest, ["proposed"], "approved", "Explicit operator approval", null, operator)) {
      throw new Error("Proposal is not awaiting approval");
    }
    return this.o.ledger.get(digest);
  }
  revoke(digest: string) {
    if (!this.o.ledger.transition(digest, ["proposed", "approved"], "revoked", "Operator revoked approval")) {
      throw new Error("Action already started; use undo");
    }
  }
  async execute(digest: string): Promise<ActionRecord> {
    const { ledger, adapter } = this.o;
    const record = ledger.get(digest);
    if (["active", "ambiguous", "conflict", "failed", "reverted", "rollback-unverified"].includes(record.status)) return record;
    this.validate(record.proposal);
    if (!record.approved_by || proposalDigest(record.proposal) !== digest ||
      !ledger.transition(digest, ["approved"], "executing", "Durable intent before resolver mutation")) {
      throw new Error("Action is not approved or is already in progress");
    }
    let mutationStarted = false;
    try {
      if (await adapter.read(record.proposal.domain)) {
        ledger.transition(digest, ["executing"], "conflict", "Existing rule preserved; no ownership assumed");
        return ledger.get(digest);
      }
      const baseline = await this.o.verify(record.proposal, "resolved");
      if (baseline.target !== "resolved" || baseline.benign !== "resolved" ||
        baseline.checked_at < record.proposal.created_at || baseline.checked_at > this.o.now()) {
        throw new Error("Baseline DNS unavailable; no mutation");
      }
      this.validate(record.proposal);
      mutationStarted = true;
      await adapter.create(ownedRule(record));
      const actual = await adapter.read(record.proposal.domain);
      if (!actual || !matches(actual, ownedRule(record))) throw new Error("Post-write ownership unknown");
      const v = await this.o.verify(record.proposal, "blocked");
      if (v.target !== "blocked" || v.benign !== "resolved" || v.checked_at < record.proposal.created_at ||
        v.checked_at > this.o.now() || record.proposal.expires_at <= this.o.now() ||
        record.proposal.evidence_revision !== this.o.evidence_revision()) {
        ledger.transition(digest, ["executing"], "active", "Independent verification failed; rolling back", v);
        return this.undo(digest);
      }
      ledger.transition(digest, ["executing"], "active", "DNS deny independently verified", v);
    } catch {
      // A timeout does not establish whether the resolver changed: never retry creation.
      ledger.transition(digest, ["executing"], mutationStarted ? "ambiguous" : "failed",
        mutationStarted ? "Mutation outcome unknown; inspect or undo owned rule" : "Preflight failed; resolver unchanged");
    }
    return ledger.get(digest);
  }
  async undo(digest: string): Promise<ActionRecord> {
    const { ledger, adapter } = this.o;
    const record = ledger.get(digest);
    if (!ledger.transition(digest, ["active", "ambiguous", "rollback-unverified"], "undoing", "Checking rule ownership before rollback")) return record;
    try {
      this.validate(record.proposal, false);
      if (proposalDigest(record.proposal) !== digest) throw new Error("Journal content changed");
      const actual = await adapter.read(record.proposal.domain);
      if (actual && !matches(actual, ownedRule(record))) {
        ledger.transition(digest, ["undoing"], "conflict", "Rule changed externally; preserved for operator review");
        return ledger.get(digest);
      }
      if (actual) await adapter.remove(record.proposal.domain);
      if (await adapter.read(record.proposal.domain)) throw new Error("Rule remains after undo");
      const v = await this.o.verify(record.proposal, "resolved");
      const restored = v.target === "resolved" && v.benign === "resolved" &&
        v.checked_at >= record.proposal.created_at && v.checked_at <= this.o.now();
      ledger.transition(digest, ["undoing"], restored ? "reverted" : "rollback-unverified",
        restored ? "Owned rule absent and DNS restored" : "Rule absent; DNS restoration remains unverified", v);
    } catch {
      ledger.transition(digest, ["undoing"], "rollback-unverified", "Rollback outcome unknown; inspect before further action");
    }
    return ledger.get(digest);
  }
  /** recoverInterrupted is only safe at exclusive startup, before serving requests. */
  async reconcile(recoverInterrupted = false): Promise<ActionRecord[]> {
    for (const record of this.o.ledger.list()) {
      if (recoverInterrupted && record.status === "executing") this.o.ledger.transition(record.digest, ["executing"], "ambiguous", "Interrupted execution; no retry");
      if (recoverInterrupted && record.status === "undoing") this.o.ledger.transition(record.digest, ["undoing"], "rollback-unverified", "Interrupted rollback");
      if (record.proposal.expires_at <= this.o.now() && ["active", "ambiguous"].includes(this.o.ledger.get(record.digest).status)) {
        await this.undo(record.digest);
      }
    }
    return this.o.ledger.list();
  }
}
