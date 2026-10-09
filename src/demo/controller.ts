import { ActionService, SqliteLedger, type DnsAdapter, type Proposal, type Verification } from "../actions";
import { AgentLoop, type AgentProvider, type AgentReport, type Trace } from "../agent";
import { baseline, type Classifier, type DecisionInput, type Judgment } from "../decisions";
import type { ReplayResult } from "../replay/evaluate";
import type { Finding } from "../domain/finding";
import type { Command } from "./http";
import { scope, target } from "./evidence";
import type { DemoSponsors } from "./sponsors";
import type { DemoGuidance } from "./guidance";
import type { DemoRouter, RouterCommand } from "./router";
import type { CapturedLogs } from "./logs";
import type { DemoChat } from "./chat";

interface Options {
  ledger: SqliteLedger; adapter: DnsAdapter; group: number; now: () => number;
  verify(p: Proposal, expected: "blocked" | "resolved"): Promise<Verification>;
  collect(from: number): Promise<ReplayResult>;
  classifiers: Classifier[];
  agent: AgentProvider;
  sponsors?: DemoSponsors;
  guidance?: DemoGuidance;
  router?: DemoRouter;
  deployment?: "mac-lab" | "pi-hybrid";
  logs?: CapturedLogs;
  chat?: DemoChat;
  incidents?: { snapshot(): unknown };
}
export class DemoController {
  private evidence: ReplayResult | null = null;
  private finding: Finding | null = null;
  private measured: Verification | null = null;
  private judgments: Judgment[] = [];
  private report: AgentReport | null = null;
  private reportAt: number | null = null;
  private observedAt = 0;
  private actionBusy = false;
  private chatBusy = false;
  readonly actions: ActionService;
  constructor(private o: Options) {
    this.actions = new ActionService({ ...o, policy: { network_scope: scope, resolver_id: "pihole-lab", group_id: o.group,
      allowed_domains: [target], max_duration_ms: 120_000 }, evidence_revision: () => this.revision() });
  }
  private revision() { return this.fresh() ? this.finding!.evidence_revision : ""; }
  private fresh() { return this.finding !== null && this.o.now() >= this.observedAt && this.o.now() - this.observedAt <= 60_000; }
  private proposal(): Proposal {
    if (!this.fresh() || this.measured?.target !== "resolved" || this.measured.benign !== "resolved") throw new Error("Fresh measured finding required");
    return { action: "dns-deny", network_scope: scope, resolver_id: "pihole-lab", domain: target, group_id: this.o.group,
      evidence_revision: this.revision(), created_at: this.o.now(), expires_at: this.o.now() + 120_000 };
  }
  private input(): DecisionInput {
    return { evidence_revision: this.revision(), evidence_ids: [...(this.finding?.evidence_ids ?? [])], coverage: this.fresh() ? "fresh" : "stale", mode: "vm-live",
      facts: { queries: this.evidence?.observations.filter(x => x.kind === "dns_query").length ?? 0,
        lab_indicator_match: this.finding?.rule_id === "flagged-test-domain", novel_domain: false, benign_probe_ok: this.measured?.benign === "resolved" } };
  }
  private traces(): Trace[] {
    const observations: Trace[] = this.finding ? [{ id: "trace:" + this.finding.evidence_revision, at: this.observedAt,
      kind: "observation", mode: "vm-live", summary: "Hedgerow triggered a controlled DNS test on its owned lab client and collected that query from Pi-hole. This is not an independently detected attack or proof of malware.",
      evidence_ids: [...this.finding.evidence_ids] }] : [];
    return [...observations, ...this.o.ledger.list().filter(r => r.proposal.evidence_revision === this.finding?.evidence_revision).flatMap(record => this.o.ledger.history(record.digest).map(event => ({
      id: `trace:action-${event.seq}`, at: event.at ?? 0, kind: event.status, mode: event.verification?.mode ?? "vm-live" as const,
      summary: `Action state: ${event.status}. Target probe: ${event.verification?.target ?? "not measured"}. Benign probe: ${event.verification?.benign ?? "not measured"}.`,
      evidence_ids: record.proposal.evidence_revision === this.finding?.evidence_revision ? [...this.finding.evidence_ids] : [],
    })))];
  }
  state() {
    return { product: "Hedgerow", mode: "vm-live", topology: this.o.deployment === "pi-hybrid"
      ? "Pi-hosted controller; Mac-hosted isolated lab over direct Ethernet SSH tunnels. Probe evidence remains VM-live."
      : "Mac-hosted controller and isolated containers in Docker Desktop VM; not physical appliance deployment",
      coverage: this.fresh() ? "fresh owned-client evidence" : "no fresh owned-client finding", evidence: this.evidence,
      finding: this.finding, measured: this.measured, judgments: this.judgments, agent: this.report, agent_at: this.reportAt,
      actions: this.o.ledger.list(), traces: this.traces(), now: this.o.now(), sponsors: this.o.sponsors?.snapshot() ?? null,
      guidance: this.o.guidance?.snapshot() ?? null,
      router: this.o.router?.snapshot() ?? null,
      logs: this.o.logs?.snapshot() ?? null,
      chat: this.o.chat?.snapshot() ?? null, incidents: this.o.incidents?.snapshot() ?? null,
      limits: "DNS denial covers one configured client group, not other resolvers or existing connections. Router hardening is a fixed owned container demonstration, not proof of consumer-router compatibility." };
  }
  async reconcile(startup = false) {
    if (this.actionBusy) return;
    if (!startup && !this.o.ledger.list().some(r => r.proposal.expires_at <= this.o.now() && ["active", "ambiguous"].includes(r.status))) return;
    this.actionBusy = true;
    try { await this.actions.reconcile(startup); } finally {
      this.actionBusy = false; this.o.sponsors?.schedule(this.o.ledger, this.evidence);
    }
  }
  async command(name: Command, input: { digest?: string; message?: string }) {
    const isChat = name === "chat";
    if (isChat ? this.chatBusy : this.actionBusy) throw new Error("Operation in progress");
    if (isChat) this.chatBusy = true;
    else this.actionBusy = true;
    const refs=()=>this.evidence?.observations.filter(x=>x.kind==="dns_query").map(x=>x.evidence_ref)??[];
    this.o.logs?.event(name, `Requested: ${name}.`, name==="observe"||name.startsWith("router-")?[]:refs());
    try {
      await this.dispatch(name, input);
      this.o.logs?.event(name, `Completed: ${name}.`, refs());
      if(name==="classify"||name==="router-classify"){
        const judgments=name==="classify"?this.judgments:this.o.router?.snapshot().judgments??[];
        for(const j of judgments)this.o.logs?.event("model-result",`${j.model}: ${j.category} (${j.inference_status}).`,name==="classify"?refs():[]);
      }
      if(name==="execute"||name==="router-execute"){
        const report=name==="execute"?this.report:this.o.router?.snapshot().agent;
        for(const call of report?.calls??[])this.o.logs?.event("agent-tool",`OpenAI tool ${call.name}: ${call.ok?"returned successfully":"failed"}. Recorded after agent run.`,name==="execute"?refs():[]);
      }
    } catch(error) {
      this.o.logs?.event("operation-failed",`${name} did not complete. Inspect measured state; no success assumed.`,refs());
      throw error;
    } finally {
      if (isChat) this.chatBusy = false;
      else {
        this.actionBusy = false;
        this.o.sponsors?.schedule(this.o.ledger, this.evidence);
      }
    }
    return this.state();
  }
  private async dispatch(name: Command, input: { digest?: string; message?: string }) {
    if(name==="chat"){
      if(!this.o.chat||!input.message)throw Error("Chat unavailable");
      await this.o.chat.send(input.message,{
        logs:(this.o.logs?.snapshot().rows??[]).slice(0,30).map(r=>({...r,observed_at:new Date(r.observed_at).toISOString(),captured_at:new Date(r.captured_at).toISOString(),indicator:String(r.indicator),closed:true as const})),
        incidents:[this.o.incidents?.snapshot()??{}],judgments:this.judgments,
        actions:this.o.ledger.list().slice(-5).map(a=>({status:a.status,verification:a.verification,domain:a.proposal.domain,expires_at:a.proposal.expires_at}))});
      return;
    }
    if (name.startsWith("router-")) {
      if (!this.o.router) throw new Error("Router lab is not configured");
      await this.o.router.command(name as RouterCommand, input.digest);
      return;
    }
    if (name === "reset") {
      if (this.o.ledger.list().some(r => ["active", "executing", "ambiguous", "undoing", "rollback-unverified"].includes(r.status))) throw new Error("Undo and verify the current change before resetting the view");
      for (const record of this.o.ledger.list()) if (["proposed", "approved"].includes(record.status)) this.actions.revoke(record.digest);
      this.evidence = null; this.finding = null; this.measured = null; this.judgments = []; this.report = null; this.reportAt = null; this.observedAt = 0;
      return this.state();
    }
    if (name === "observe") {
      if (this.o.ledger.list().some(r => ["active", "executing", "ambiguous", "undoing", "rollback-unverified"].includes(r.status))) throw new Error("Resolve the current action before starting another incident");
      this.evidence = null; this.finding = null; this.measured = null; this.judgments = []; this.report = null; this.reportAt = null;
      const now = this.o.now();
      this.measured = await this.o.verify({ action: "dns-deny", network_scope: scope, resolver_id: "pihole-lab", domain: target,
        group_id: this.o.group, evidence_revision: "baseline", created_at: now, expires_at: now + 120_000 }, "resolved");
      this.evidence = await this.o.collect(now);
      this.finding = this.evidence.findings.find(f => f.rule_id === "flagged-test-domain" && f.state === "observed" && f.mode === "vm-live") ?? null;
      const observation = this.evidence.observations.find(x => this.finding?.evidence_ids.includes(x.id));
      this.observedAt = observation ? Date.parse(observation.observed_at) : 0;
    } else if (name === "classify") {
      this.judgments = [baseline(this.input()), ...await Promise.all(this.o.classifiers.map(c => c.classify(this.input())))];
    } else if (name === "propose") {
      const proposal = this.proposal();
      const existing = this.o.ledger.list().find(r => r.status === "proposed" && r.proposal.evidence_revision === proposal.evidence_revision && r.proposal.expires_at > this.o.now());
      if (!existing) this.actions.propose(proposal);
    } else {
      if (!input.digest || !/^[a-f0-9]{64}$/.test(input.digest)) throw new Error("Exact digest required");
      if (name === "approve") { this.proposal(); this.actions.approve(input.digest, "oc-local-browser"); }
      else if (name === "undo") await this.actions.undo(input.digest);
      else if (name === "execute") {
        const record = this.o.ledger.get(input.digest);
        if (record.status !== "approved" || !this.fresh()) throw new Error("Fresh exact human approval required");
        const loop = new AgentLoop({ revision: () => this.revision(), traces: () => this.traces(),
          finding: (kind, revision) => kind === "dns-deny" && revision === this.revision() ? this.finding?.id ?? null : null,
          // This run executes one human-selected proposal; re-proposing must not substitute a new digest.
          propose: async kind => { if (kind !== "dns-deny") throw new Error("Unsupported adapter"); return this.o.ledger.get(input.digest!); },
          execute: async digest => { if (digest !== input.digest) throw new Error("Outside this human request"); return this.actions.execute(digest); },
          status: async digest => this.o.ledger.get(digest),
        }, this.o.agent);
        this.report = await loop.run({ evidence_revision: this.revision(), proposal_digests: [input.digest],
          judgment: this.judgments.find(j => j.provenance === "hosted")?.category ?? "unknown" });
        this.reportAt = this.o.now();
      }
    }
    return this.state();
  }
}
