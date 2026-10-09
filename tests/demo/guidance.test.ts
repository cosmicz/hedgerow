import { expect, test } from "bun:test";
import { DemoGuidance } from "../../src/demo/guidance";

test("guidance requests only fixed public topics, exposes cited results and caches once", async () => {
  const topics: string[] = [];
  const guidance = new DemoGuidance({ guidance: async topic => {
    topics.push(topic); return { status: "unavailable", topic, reason: "not configured" };
  }});
  expect(guidance.snapshot().status).toBe("not-requested");
  guidance.start(); guidance.start(); await guidance.settled();
  expect(topics).toEqual(["dns-deny-limits", "measured-vs-model"]);
  expect(guidance.snapshot().status).toBe("unavailable");
  expect(guidance.snapshot().results).toHaveLength(2);
  guidance.start(); await guidance.settled(); expect(topics).toHaveLength(2);
});

test("hung guidance cannot hold the caller or publish late results", async () => {
  let release!: () => void;
  const guidance = new DemoGuidance({ guidance: async topic => {
    await new Promise<void>(r => { release = r; });
    return { status: "unavailable", topic, reason: "late result" };
  }}, 10);
  guidance.start(); await guidance.settled();
  expect(guidance.snapshot().status).toBe("unavailable");
  release(); await Bun.sleep(1);
  expect(guidance.snapshot().results).toHaveLength(0);
  expect(JSON.stringify(guidance.snapshot())).not.toContain("PRIVATE_MARKER");
});

test("unexpected provider exceptions never appear in the UI", async () => {
  const guidance = new DemoGuidance({ guidance: async () => { throw Error("PRIVATE_MARKER"); } });
  guidance.start(); await guidance.settled();
  expect(guidance.snapshot().status).toBe("unavailable");
  expect(JSON.stringify(guidance.snapshot())).not.toContain("PRIVATE_MARKER");
});

test("successful guidance retains both cited results and retrieval time", async () => {
  const id = "04d2a35e-492d-43ea-a221-fddafd9f53f0";
  const document = { sha256: "a".repeat(64), title: "Test public guide", content_id: id, kb_node_id: id };
  const guidance = new DemoGuidance({ guidance: async topic => ({ status: "ok", topic, query: "fixed topic",
    passages: [{ content_id: id, kb_node_id: id, title: document.title, text: "Reference, not authority", score: 1, rank: 1 }],
    citations: [id], document, latency_ms: 1 }) });
  guidance.start(); await guidance.settled();
  expect(guidance.snapshot().status).toBe("ready");
  expect(guidance.snapshot().results).toHaveLength(2);
  expect(guidance.snapshot().completed_at).not.toBeNull();
  const result = guidance.snapshot().results[0];
  expect(result?.status === "ok" && result.citations).toEqual([id]);
});
