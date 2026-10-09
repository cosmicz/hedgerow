import type { SqliteLedger } from "../actions";
import { SponsorBridge, type Sourced, type SourcedEvidence, type ProjectedAction } from "../adapters/sponsors";
import type { ReplayResult } from "../replay/evaluate";
import { scope, target } from "./evidence";

/** Read-side evidence only. No callback from this object can authorize an action. */
export class DemoSponsors {
  private evidence: SourcedEvidence | null = null;
  private actions: Sourced<readonly ProjectedAction[]> | null = null;
  private error: string | null = null;
  private checkedAt: number | null = null;
  private evidenceRevision: string | null = null;
  private mirrored = new Map<string, string>();
  private disabled = false;
  private pending: { ledger: SqliteLedger; source: ReplayResult | null } | null = null;
  private running: Promise<void> | null = null;
  constructor(private bridge: SponsorBridge, private timeoutMs = 2000) {}

  snapshot() {
    return { report: this.bridge.status(), evidence: this.evidence, actions: this.actions,
      error: this.error, checked_at: this.checkedAt, evidence_revision: this.evidenceRevision };
  }

  /** Coalesce reads in the background. Command/Undo never waits for sponsor I/O. */
  schedule(ledger: SqliteLedger, source: ReplayResult | null) {
    if (this.disabled) return;
    this.pending = { ledger, source };
    if (this.running) return;
    this.running = this.drain().finally(() => { this.running = null; });
  }
  settled(): Promise<void> { return this.running ?? Promise.resolve(); }
  private async drain() {
    while (this.pending && !this.disabled) {
      const next = this.pending; this.pending = null;
      await this.refresh(next.ledger, next.source);
    }
    this.pending = null;
  }

  async refresh(ledger: SqliteLedger, source: ReplayResult | null) {
    if (this.disabled) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        this.read(ledger, source).then(result => {
          // A late read must not overwrite the timed-out snapshot or re-enable the sidecar.
          if (this.disabled) return;
          this.evidence = result.evidence; this.actions = result.actions;
          this.evidenceRevision = source?.findings.find(f => f.rule_id === "flagged-test-domain")?.evidence_revision ?? null;
          this.error = result.complete ? null : "Sponsor journal projection is incomplete; consult the local action journal.";
          this.checkedAt = Date.now();
        }),
        new Promise<void>(resolve => { timer = setTimeout(() => {
          this.disabled = true;
          this.error = "Sponsor refresh timed out and is disabled for this session; retained audit copies may be stale. The local action journal and Undo remain available.";
          resolve();
        }, this.timeoutMs); }),
      ]);
    } catch {
      // Backend diagnostics are not user content and must not mask a completed action.
      this.error = "Sponsor evidence is unavailable; the local action journal remains authoritative.";
    } finally { if (timer) clearTimeout(timer); }
  }

  private async read(ledger: SqliteLedger, source: ReplayResult | null) {
    let evidence: SourcedEvidence | null = null;
    if (source) {
      await this.bridge.recordObservations(source.observations);
      const times = source.observations.filter(o => o.kind === "dns_query").map(o => Date.parse(o.observed_at));
      evidence = times.length ? await this.bridge.evidence({ domain: target, network_scope: scope,
        from: new Date(Math.min(...times)).toISOString(), to: new Date(Math.max(...times) + 1).toISOString() }) : null;
    }
    let complete = true;
    for (const record of ledger.list()) {
      if (this.disabled) return { evidence: null, actions: null, complete: false };
      const fingerprint = JSON.stringify([record, ledger.history(record.digest)]);
      if (this.mirrored.get(record.digest) === fingerprint) continue;
      const ok = (await this.bridge.mirrorJournal(ledger, record.digest)).ok;
      if (ok && !this.disabled) this.mirrored.set(record.digest, fingerprint);
      complete = ok && complete;
    }
    return { evidence, actions: await this.bridge.actions(scope), complete };
  }
}
