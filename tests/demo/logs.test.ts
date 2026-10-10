import { expect, test } from "bun:test";
import { CapturedLogs, projectQueryLogs } from "../../src/demo/logs";
import traffic from "../../lab/traffic-domains.json";
const now = 1_800_000_000_000;
const row = { id: 7, time: now / 1000, domain: "flagged.lab.test", type: "A", status: "CACHE", client: { ip: "10.77.0.100", name: "private hostname" }, reply: { type: "IP" } };
test("captures operator-selected web domains without admitting arbitrary traffic", () => {
  const domains=traffic.domains;
  expect(new Set(domains).size).toBe(50);
  expect(domains.every(d=>/^[a-z0-9.-]+$/.test(d))).toBe(true);
  const rows=projectQueryLogs({queries:[...domains,"private.example","pornhub.com"].map((domain,id)=>({...row,id,domain}))},now);
  expect(rows.map(r=>r.domain)).toEqual(domains);
  expect(rows.every(r=>!r.indicator)).toBe(true);
});
test("captured rows retain source IDs and times, exclude unrelated traffic and arbitrary text", () => {
  const rows = projectQueryLogs({ queries: [row, {...row,id:8,domain:"benign.lab.test"}, {...row,id:9,domain:"private.example"}, {...row,id:10,client:{ip:"10.77.0.101"}}] }, now);
  expect(rows).toHaveLength(2);
  expect(rows[0]?.id).toBe("pihole:query:7");
  expect(rows[0]?.observed_at).toBe(now);
  expect(rows[0]?.indicator).toBe(true);
  expect(JSON.stringify(rows)).not.toMatch(/private/);
  expect(() => projectQueryLogs({}, now)).toThrow();
});
test("log history deduplicates capture, retains events and reports collection failures honestly", async () => {
  let fail=false;
  const logs=new CapturedLogs(":memory:",async()=>{if(fail)throw Error("secret");return {queries:[row]};},()=>now);
  try {
    expect(logs.snapshot().rows).toHaveLength(0);
    await logs.poll(); await logs.poll();
    expect(logs.snapshot().rows).toHaveLength(1);
    logs.event("classify", "Jev and Clef requested", ["pihole:query:7"]);
    expect(logs.snapshot().events[0]?.evidence_refs).toEqual(["pihole:query:7"]);
    fail=true; await logs.poll();
    expect(logs.snapshot().status).toBe("unavailable");
    expect(logs.snapshot().rows).toHaveLength(1);
    expect(JSON.stringify(logs.snapshot())).not.toContain("secret");
  } finally {logs.close();}
});
