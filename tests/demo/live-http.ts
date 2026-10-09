import { expect } from "bun:test";
if (process.env.RG_DEMO_LIVE !== "1") throw new Error("Explicit RG_DEMO_LIVE=1 and exclusive owned lab window required");
const base = "http://127.0.0.1:8787";
const { token } = await (await fetch(base + "/api/session")).json() as { token: string };
const frames: unknown[] = [];
let digest: string | undefined;
let failure: string | null = null;
async function call(name: string, input: unknown = {}): Promise<any> {
  const response = await fetch(base + "/api/" + name, { method: "POST", signal: AbortSignal.timeout(120_000),
    headers: { Origin: base, "Content-Type": "application/json", "X-Hedgerow-CSRF": token }, body: JSON.stringify(input) });
  const state: any = await response.json();
  frames.push({ step: name, at: new Date().toISOString(), status: response.status, state });
  console.log(JSON.stringify({ step: name, http: response.status, finding: state.finding?.rule_id,
    actions: state.actions?.map((a: any) => ({ status: a.status, verification: a.verification })),
    models: state.judgments?.map((j: any) => ({ model: j.model, category: j.category, inference: j.inference_status })),
    agent: state.agent ? { status: state.agent.status, calls: state.agent.calls.map((c: any) => ({ name: c.name, ok: c.ok })) } : null }));
  if (!response.ok) throw new Error(`HTTP command ${name} failed; inspect retained evidence`);
  return state;
}
async function sponsorState(step: string, ready: (state: any) => boolean): Promise<any> {
  for (let attempt = 0; attempt < 30; attempt++) {
    const response = await fetch(base + "/api/state", { signal: AbortSignal.timeout(5000) });
    const state: any = await response.json();
    if (response.ok && ready(state)) {
      frames.push({ step, at: new Date().toISOString(), status: response.status, state });
      return state;
    }
    await Bun.sleep(200);
  }
  throw new Error("Sponsor audit did not catch up; no completed integration is assumed");
}
try {
  const observed = await call("observe");
  expect(observed.finding?.rule_id).toBe("flagged-test-domain");
  if (process.env.RG_DEMO_SPONSORS === "1") {
    const mirrored = await sponsorState("sponsor-observation", s => s.sponsors?.evidence?.evidence.observation_ids.some((id: string) => observed.finding.evidence_ids.includes(id)));
    expect(mirrored.sponsors.evidence.backend).toBe("clickhouse");
    expect(mirrored.sponsors.evidence.evidence.lookups).toBeGreaterThan(0);
    expect(mirrored.sponsors.report.security_scan.status).toBe("passed");
    expect(mirrored.sponsors.report.security_scan.worktree_dirty).toBe(false);
  }
  const classified = await call("classify");
  expect(classified.judgments.filter((j: any) => j.provenance === "hosted" && j.inference_status === "succeeded")).toHaveLength(2);
  const proposed = await call("propose"); digest = proposed.actions.at(-1).digest;
  await call("approve", { digest });
  const applied = await call("execute", { digest });
  const action = applied.actions.find((a: any) => a.digest === digest);
  expect(action.status).toBe("active");
  expect(action.verification.target).toBe("blocked");
  expect(action.verification.benign).toBe("resolved");
  expect(applied.agent?.status).toBe("complete");
  expect(applied.agent.calls.some((c: any) => c.name === "execute_approved" && c.ok)).toBe(true);
} catch (error) { failure = String(error); }
finally {
  if (digest) {
    try {
      const restored = await call("undo", { digest });
      const action = restored.actions.find((a: any) => a.digest === digest);
      expect(action.status).toBe("reverted");
      expect(action.verification.target).toBe("resolved");
      expect(action.verification.benign).toBe("resolved");
      if (process.env.RG_DEMO_SPONSORS === "1") {
        const mirrored = await sponsorState("sponsor-restoration", s => s.sponsors?.actions?.value.some((a: any) => a.digest === digest && a.status === "reverted"));
        expect(mirrored.sponsors.actions.backend).toBe("mongodb");
        expect(mirrored.sponsors.error).toBeNull();
      }
    } catch (error) { failure = `${failure ?? ""}; undo: ${String(error)}`; }
  }
  const revision = Bun.spawnSync(["git", "rev-parse", "HEAD"]).stdout.toString().trim();
  const worktree_status = Bun.spawnSync(["git", "status", "--porcelain"]).stdout.toString();
  const artifact = { revision, worktree_status, topology: "isolated containers inside Docker Desktop VM",
    approval: "operator-authorized automated integration test, not a human recording", failure, frames };
  const path = `private/demo/live-${Date.now()}.json`;
  await Bun.write(path, JSON.stringify(artifact, null, 2));
  console.log(JSON.stringify({ evidence: path, sha256: new Bun.CryptoHasher("sha256").update(await Bun.file(path).arrayBuffer()).digest("hex"), failure }));
}
if (failure) process.exit(1);
