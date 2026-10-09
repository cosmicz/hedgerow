import { expect, test } from "bun:test";
import { classifyRouter, routerFacts, type RouterAttempt } from "../../src/decisions/router";

const now = Date.parse("2026-10-09T22:40:00.000Z");
const revision = `sha256:${"c".repeat(64)}`;
const at = (offset: number) => new Date(now + offset).toISOString();
const attempt = (role: RouterAttempt["role"], outcome: RouterAttempt["outcome"], offset = -2000): RouterAttempt =>
  ({ role, outcome, started_at: at(offset), finished_at: at(offset + 300) });
const misuse = [attempt("unrelated", "rejected", -4000), attempt("seeded-before", "accepted")];
const rotated = [...misuse, attempt("seeded-after", "rejected", -1500), attempt("replacement", "accepted", -1000)];
const answer = (choice: string, model: string) => ({ model, provider: "Fixture",
  answers: { category: { type: "choice", choice, confidence: 0.8,
    probabilities: { benign: choice === "benign" ? 0.8 : 0.1, suspicious: choice === "suspicious" ? 0.8 : 0.1, unknown: choice === "unknown" ? 0.8 : 0.1 } } },
  usage: { cost: 0.00002 } });
function recorder(choice = "suspicious") {
  const bodies: any[] = []; const headers: Headers[] = [];
  const fetcher = async (_url: string, init?: RequestInit) => {
    bodies.push(JSON.parse(String(init?.body))); headers.push(new Headers(init?.headers));
    const model = bodies.at(-1).model;
    return Response.json(answer(choice, model === "typesafe/jev-1.13" ? "typesafe/jev-1.13-20260917" : model));
  };
  return { bodies, headers, fetcher };
}

test("seeded lab credential accepted while an unrelated one is rejected is suspicious lab misuse, not malware", async () => {
  const r = recorder();
  const judgments = await classifyRouter(misuse, revision, now, () => "test-key", r.fetcher);
  expect(judgments.map(j => [j.provenance, j.model, j.category, j.inference_status])).toEqual([
    ["deterministic", "router-rules-v1", "suspicious", "not-called"],
    ["hosted", "typesafe/jev-1.13-20260917", "suspicious", "succeeded"],
    ["hosted", "cloudflare/clef", "suspicious", "succeeded"],
  ]);
  expect(judgments[0]!.reason).toContain("not malware");
  expect(judgments.every(j => j.recommendation !== "propose-block")).toBe(true);
  expect(judgments.every(j => j.evidence_revision === revision)).toBe(true);
  expect(r.bodies).toHaveLength(2);
});

test("only a closed projection of fixed booleans and counts leaves the process", async () => {
  const r = recorder();
  const hostile = misuse.map(a => ({ ...a, host: "10.77.0.2", stderr: "SECRET dbclient stderr", password: "SECRET-PASS" })) as RouterAttempt[];
  await classifyRouter(hostile, revision, now, () => "test-key", r.fetcher);
  for (const body of r.bodies) {
    expect(Object.keys(body.state).sort()).toEqual(["facts", "scope"]);
    expect(Object.keys(body.state.facts).sort()).toEqual(Object.keys(routerFacts(misuse)!).sort());
    expect(Object.values(body.state.facts).every(v => typeof v === "boolean" || typeof v === "number")).toBe(true);
    const text = JSON.stringify(body);
    for (const leak of ["SECRET", "10.77", revision, at(-2000)]) expect(text).not.toContain(leak);
  }
  expect(r.headers[0]!.get("Authorization")).toBe("Bearer test-key");
});

test("completed rotation is benign at baseline: the seeded credential is no longer accepted", async () => {
  const judgments = await classifyRouter(rotated, revision, now, () => "test-key", recorder("benign").fetcher);
  expect(judgments[0]!.category).toBe("benign");
  expect(judgments[0]!.recommendation).toBe("observe");
});

test("missing, stale, future, malformed, errored or inconsistent evidence is unknown and never sent", async () => {
  const cases: [string, unknown, string?][] = [
    ["empty", []],
    ["missing unrelated", [attempt("seeded-before", "accepted")]],
    ["error outcome", [attempt("unrelated", "error"), attempt("seeded-before", "accepted")]],
    ["error after rotation", [...misuse, attempt("seeded-after", "error", -1500), attempt("replacement", "accepted", -1000)]],
    ["half rotation", [...misuse, attempt("replacement", "accepted", -1000)]],
    ["stale", misuse.map(a => ({ ...a, started_at: at(-200_000), finished_at: at(-199_000) }))],
    ["future", misuse.map(a => ({ ...a, finished_at: at(30_000) }))],
    ["finished before started", misuse.map(a => ({ ...a, started_at: at(-100), finished_at: at(-900) }))],
    ["bad role", [{ ...misuse[0], role: "attacker" }, misuse[1]]],
    ["duplicate role", [...misuse, attempt("seeded-before", "accepted")]],
    ["unrelated accepted", [attempt("unrelated", "accepted"), attempt("seeded-before", "accepted")]],
    ["bad revision", misuse, "not-a-revision"],
  ];
  for (const [name, attempts, rev] of cases) {
    const r = recorder();
    const judgments = await classifyRouter(attempts as RouterAttempt[], rev ?? revision, now, () => "test-key", r.fetcher);
    expect({ name, sent: r.bodies.length }).toEqual({ name, sent: 0 });
    expect({ name, categories: judgments.map(j => j.category) }).toEqual({ name, categories: ["unknown", "unknown", "unknown"] });
    expect(judgments.every(j => j.inference_status === "not-called" && j.recommendation === "ask")).toBe(true);
  }
});

test("provider outage, malformed answers and a missing key abstain without authority", async () => {
  const failing = async () => { throw new Error("SECRET network detail"); };
  const outage = await classifyRouter(misuse, revision, now, () => "test-key", failing);
  expect(outage[0]!.category).toBe("suspicious");
  expect(outage.slice(1).map(j => [j.category, j.inference_status])).toEqual([["unknown", "failed"], ["unknown", "failed"]]);
  expect(JSON.stringify(outage)).not.toContain("SECRET");

  const malformed = async () => Response.json({ model: "cloudflare/clef", answers: { category: { type: "choice", choice: "approve-rotation" } } });
  expect((await classifyRouter(misuse, revision, now, () => "test-key", malformed)).slice(1).every(j => j.category === "unknown" && j.inference_status === "failed")).toBe(true);

  const wrongModel = async () => Response.json(answer("suspicious", "attacker/model"));
  expect((await classifyRouter(misuse, revision, now, () => "test-key", wrongModel)).slice(1).every(j => j.inference_status === "failed")).toBe(true);

  const r = recorder();
  const keyless = await classifyRouter(misuse, revision, now, () => "", r.fetcher);
  expect(r.bodies).toHaveLength(0);
  expect(keyless.slice(1).every(j => j.category === "unknown" && j.inference_status === "not-called")).toBe(true);
});

test("a hung provider is aborted and abstains", async () => {
  let aborted = 0;
  const hung = (_url: string, init?: RequestInit) => new Promise<Response>((_, reject) => {
    init?.signal?.addEventListener("abort", () => { aborted++; reject(new Error("aborted")); });
  });
  const judgments = await classifyRouter(misuse, revision, now, () => "test-key", hung, 20);
  expect(aborted).toBe(2);
  expect(judgments.slice(1).every(j => j.category === "unknown" && j.inference_status === "failed")).toBe(true);
});
