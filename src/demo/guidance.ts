import type { GuidanceResult, GuidanceTopic, SensoGuidance } from "../adapters/sponsors";

/** Public reference material is optional, cached, and never on the action path. */
export class DemoGuidance {
  private status: "not-requested" | "loading" | "ready" | "partial" | "unavailable" = "not-requested";
  private results: GuidanceResult[] = [];
  private requestedAt: number | null = null;
  private completedAt: number | null = null;
  private running: Promise<void> | null = null;
  private expired = false;
  constructor(private provider: Pick<SensoGuidance, "guidance">, private timeoutMs = 15000) {}
  snapshot() { return { status: this.status, results: this.results, requested_at: this.requestedAt, completed_at: this.completedAt }; }
  start() {
    if (this.status !== "not-requested") return;
    this.status = "loading"; this.requestedAt = Date.now();
    this.running = this.load();
  }
  settled() { return this.running ?? Promise.resolve(); }
  private async load() {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        this.retrieve().then(results => {
          if (this.expired) return;
          this.results = results;
          const available = results.filter(r => r.status === "ok").length;
          this.status = available === 2 ? "ready" : available ? "partial" : "unavailable";
          this.completedAt = Date.now();
        }),
        new Promise<void>(resolve => { timer = setTimeout(() => { this.expired = true; this.status = "unavailable"; resolve(); }, this.timeoutMs); }),
      ]);
    } catch {
      this.expired = true; this.status = "unavailable";
    } finally { if (timer) clearTimeout(timer); }
  }
  private async retrieve() {
    const results: GuidanceResult[] = [];
    for (const topic of ["dns-deny-limits", "measured-vs-model"] as GuidanceTopic[]) {
      if (this.expired) break;
      results.push(await this.provider.guidance(topic));
    }
    return results;
  }
}
