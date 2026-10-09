import { AgentLoop, type AgentProvider, type AgentReport, type Trace, type ToolResult } from "../agent";
import type { Judgment } from "../decisions";
import type { RouterLabController, RedactedAuthAttempt } from "../router/controller";
import { credentialRotationTrace, type CredentialRotationTrace } from "../router/trace";

interface Options {
  backend: RouterLabController;
  agent: AgentProvider;
  now(): number;
  classify(attempts: readonly RedactedAuthAttempt[], revision: string, now: number): Promise<Judgment[]>;
}
export type RouterCommand = "router-prepare" | "router-attack" | "router-classify" | "router-propose" | "router-approve" | "router-execute" | "router-cleanup";

/** Thin UI/agent boundary. The backend separately owns durable approval and target checks. */
export class DemoRouter {
  private phase = "down";
  private revision = "";
  private observedAt = 0;
  private attempts: readonly RedactedAuthAttempt[] = [];
  private proposal: Awaited<ReturnType<RouterLabController["propose"]>> | null = null;
  private trace: CredentialRotationTrace | null = null;
  private judgments: Judgment[] = [];
  private agent: AgentReport | null = null;
  private agentAt: number | null = null;
  constructor(private o: Options) {}
  snapshot() { return { phase: this.phase, mode: "vm-live", runtime: "OpenWrt userland container; password changed through fixed Docker exec, not a consumer router API",
    attempts: this.attempts, proposal: this.proposal, trace: this.trace, judgments: this.judgments, agent: this.agent, agent_at: this.agentAt }; }
  private fresh() { return !!this.revision && this.o.now() >= this.observedAt && this.o.now() - this.observedAt <= 300000; }
  private finding() { return this.fresh() && this.attempts.some(a => a.role === "seeded-before" && a.outcome === "accepted") &&
    this.attempts.some(a => a.role === "unrelated" && a.outcome === "rejected") && !this.attempts.some(a => a.outcome === "error"); }
  private traces(): Trace[] {
    const before: Trace[] = this.attempts.map((a, i) => ({ id: `trace:router-before-${i}-${this.revision.slice(0,16)}`, at: Date.parse(a.finished_at), kind: "authentication", mode: "vm-live",
      summary: `Controlled owned-lab authentication: ${a.role} credential ${a.outcome}. Known seeded credential only; no guessing, scan or real household traffic.`, evidence_ids: [`observation:${this.revision}`] }));
    return [...before, ...(this.trace?.attempts.map((a, i): Trace => ({ id: `trace:router-measured-${i}-${this.revision.slice(0,16)}`, at: Date.parse(a.occurred_at),
      kind: "authentication-verification", mode: "vm-live", summary: `Measured ${a.attempt}: ${a.outcome}. OpenWrt userland container, fixed docker-exec password mutation; not consumer-router compatibility proof.`, evidence_ids: [`observation:${this.revision}`] })) ?? [])];
  }
  private result(): ToolResult {
    if (!this.proposal) throw new Error("No router proposal");
    return { digest: this.proposal.digest, status: this.phase,
      verification: this.trace ? { old_login: false, new_login: true, checked_at: Date.parse(this.trace.attempts.at(-1)!.occurred_at), mode: "vm-live" } : null };
  }
  async command(name: RouterCommand, digest?: string) {
    if (name === "router-prepare") {
      if (this.phase !== "down") throw new Error("Clean up the prior router lab first");
      try { await this.o.backend.prepare(); this.phase = "prepared"; }
      catch { this.phase = "failed"; throw new Error("Router setup failed; inspect or clean up only owned objects"); }
      this.attempts = []; this.proposal = null; this.trace = null; this.judgments = []; this.agent = null; this.agentAt = null;
    } else if (name === "router-attack") {
      if (this.phase !== "prepared") throw new Error("Prepare the owned router first");
      const result = await this.o.backend.attack();
      const revision = result.evidence_revision.replace(/^sha256:/, "");
      if (!/^[a-f0-9]{64}$/.test(revision)) throw new Error("Invalid router evidence");
      this.attempts = result.attempts; this.revision = revision;
      this.observedAt = Math.max(...result.attempts.map(a => Date.parse(a.finished_at)));
      this.phase = this.finding() ? "attacked" : "failed";
    } else if (name === "router-classify") {
      this.judgments = await this.o.classify(this.attempts, this.revision, this.o.now());
    } else if (name === "router-propose") {
      if (this.phase !== "attacked" || !this.finding()) throw new Error("Fresh measured lab authentication finding required");
      this.proposal = await this.o.backend.propose(); this.phase = "proposed";
    } else if (name === "router-cleanup") {
      await this.o.backend.cleanup(); this.phase = "down";
    } else {
      if (!this.proposal || digest !== this.proposal.digest || !this.finding()) throw new Error("Exact fresh router proposal required");
      if (name === "router-approve") {
        if (this.phase !== "proposed") throw new Error("Proposal is not awaiting approval");
        await this.o.backend.approveFromUi(digest, "oc-local-browser", true); this.phase = "approved";
      } else {
        if (this.phase !== "approved") throw new Error("Persisted human approval required");
        const loop = new AgentLoop({ revision: () => this.fresh() ? this.revision : "", traces: () => this.traces(),
          finding: (kind, rev) => kind === "router-hardening" && rev === this.revision && this.finding() ? `finding:${this.revision}` : null,
          propose: async kind => { if (kind !== "router-hardening") throw new Error("Wrong adapter"); return this.result(); },
          status: async id => { if (id !== digest) throw new Error("Wrong proposal"); return this.result(); },
          execute: async id => {
            if (id !== digest || this.phase !== "approved" || !this.finding()) throw new Error("Wrong or stale approval");
            this.phase = "executing";
            try { const result = await this.o.backend.rotate(id); this.trace = credentialRotationTrace(result.trace); this.phase = "rotated"; }
            catch { this.phase = "failed"; throw new Error("Rotation outcome requires inspection; no retry"); }
            return this.result();
          },
        }, this.o.agent);
        this.agent = await loop.run({ evidence_revision: this.revision, proposal_digests: [digest], judgment: this.judgments.find(j => j.provenance === "hosted")?.category ?? "unknown" });
        this.agentAt = this.o.now();
      }
    }
    return this.snapshot();
  }
}
