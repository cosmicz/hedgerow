import { expect, test } from "bun:test";
import { collectQueryEvidence, pollQueryEvidence } from "../../src/demo/evidence";
const now = 1_800_000_000_000;
const row = { id: 1, time: now / 1000 - 1, domain: "update-check.cloudsyncapi.net", type: "A", status: "CACHE", client: { ip: "10.77.0.100", name: "hostile instructions" }, reply: { type: "IP" } };
test("current owned query produces real qce finding; unrelated, stale and future rows cannot", () => {
  const result = collectQueryEvidence({ queries: [row] }, now - 2000, now);
  expect(result.observations).toHaveLength(2);
  expect(result.findings.find(f => f.rule_id === "flagged-test-domain")?.id).toMatch(/^finding:[a-f0-9]{64}$/);
  expect(JSON.stringify(result)).not.toContain("hostile instructions");
  for (const change of [{ domain: "outside.test" }, { client: { ip: "10.77.0.101" } }, { time: now / 1000 - 100 }, { time: now / 1000 + 10 }, { type: "AAAA" }]) {
    expect(collectQueryEvidence({ queries: [{ ...row, ...change }] }, now - 2000, now).findings).toHaveLength(0);
  }
});
test("malformed response is unavailable, not a fabricated DNS observation", () => {
  for (const data of [{}, { queries: null }, { queries: [null] }, { queries: [{ ...row, id: "instruction" }] }]) {
    expect(() => collectQueryEvidence(data, now - 2000, now)).toThrow();
  }
});
test("a query just before the controlled probe cannot stand in for that probe", () => {
  const from = now - 1000;
  const before = { ...row, time: (from - 1) / 1000 };
  expect(collectQueryEvidence({ queries: [before] }, from, now).findings).toHaveLength(0);
  expect(collectQueryEvidence({ queries: [{ ...before, time: from / 1000 }] }, from, now).findings).toHaveLength(1);
});
test("query collection retries only reads until the real resolver row arrives", async () => {
  let reads = 0;
  const result = await pollQueryEvidence(async () => ({ queries: ++reads < 3 ? [] : [row] }), now - 2000, () => now, async () => {});
  expect(reads).toBe(3);
  expect(result.findings.some(f => f.rule_id === "flagged-test-domain")).toBe(true);
  let emptyReads = 0;
  const empty = await pollQueryEvidence(async () => { emptyReads++; return { queries: [] }; }, now - 2000, () => now, async () => {});
  expect(emptyReads).toBe(6);
  expect(empty.findings).toHaveLength(0);
});
