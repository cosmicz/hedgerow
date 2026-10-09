// LogClassifier: groups fresh flagged lab log lines into advisory incidents,
// labels each once through a hosted decision model over a CLOSED projection,
// and throttles to one incident (one model call) per source per 60 s.
import { describe, expect, test } from "bun:test";

import type { CapturedQuery } from "../../src/demo/logs.js";
import { LogClassifier } from "../../src/demo/log-classifier.js";

const BASE = "https://openrouter.ai/api/alpha/decisions";
const LAB_CLIENT = "10.77.0.100";

function row(over: Partial<CapturedQuery> & { id: string; observed_at: number }): CapturedQuery {
  return {
    captured_at: over.observed_at,
    domain: "flagged.lab.test",
    client: LAB_CLIENT,
    type: "A",
    status: "DENYLIST",
    reply: "IP",
    indicator: true,
    ...over,
  };
}

/** Records every request; returns a valid decisions answer with the given choice. */
function stubProvider(choice: "benign" | "suspicious" | "unknown" = "suspicious", model = "cloudflare/clef") {
  const calls: { url: string; body: any; redirect: RequestRedirect | undefined; auth: string | undefined }[] = [];
  const p = choice === "suspicious" ? { benign: 0.1, suspicious: 0.8, unknown: 0.1 } : choice === "benign" ? { benign: 0.8, suspicious: 0.1, unknown: 0.1 } : { benign: 0.2, suspicious: 0.2, unknown: 0.6 };
  const fetcher = (async (url: string, init?: RequestInit) => {
    const headers = init?.headers as Record<string, string> | undefined;
    calls.push({ url, body: JSON.parse(String(init?.body)), redirect: init?.redirect, auth: headers?.Authorization });
    return new Response(JSON.stringify({ model, provider: "openrouter", usage: { cost: 0.0004 }, answers: { category: { type: "choice", choice, confidence: Math.max(p.benign, p.suspicious, p.unknown), probabilities: p } } }), { status: 200 });
  }) as unknown as typeof fetch;
  return { calls, fetcher };
}

const opts = (fetcher: typeof fetch, now: () => number, key = () => "or_test_key") => ({ model: "cloudflare/clef" as const, key, fetcher, now, timeoutMs: 2_000 });

describe("log classifier", () => {
  test("groups fresh flagged rows into one incident labelled by the model over a closed projection", async () => {
    const now = 1_000_000_000;
    const { calls, fetcher } = stubProvider("suspicious");
    const lc = new LogClassifier(opts(fetcher, () => now));

    await lc.ingest([
      row({ id: "pihole:query:1", observed_at: now - 2_000 }),
      row({ id: "pihole:query:2", observed_at: now - 1_000 }),
      row({ id: "b1", observed_at: now - 1_500, domain: "benign.lab.test", status: "FORWARDED", indicator: false }),
    ]);
    const snap = lc.snapshot();

    expect(calls).toHaveLength(1);
    expect(snap.status).toBe("live");
    expect(snap.incidents).toHaveLength(1);
    const incident = snap.incidents[0]!;
    expect(incident).toMatchObject({ source_id: LAB_CLIENT, category: "suspicious", status: "classified" });
    expect(incident.source_ids).toEqual(["pihole:query:1", "pihole:query:2"]);
    expect(incident.judgments[0]).toMatchObject({ inference_status: "succeeded", provenance: "hosted", recommendation: "propose-block" });

    // Closed projection: flagged + benign context lines, each only whitelisted fields.
    const sent = calls[0]!.body;
    expect(sent.model).toBe("cloudflare/clef");
    expect(sent.state.lab_queries.map((q: any) => q.domain).sort()).toEqual(["benign.lab.test", "flagged.lab.test", "flagged.lab.test"]);
    for (const q of sent.state.lab_queries) {
      expect(Object.keys(q).sort()).toEqual(["client", "domain", "id", "reply", "status", "time", "type"]);
      expect(q.client).toBe(LAB_CLIENT);
      expect(q.type).toBe("A");
    }
    // The transmitted rows carry no indicator/captured_at (only the whitelist above).
    expect(JSON.stringify(sent.state.lab_queries)).not.toContain("indicator");
    expect(JSON.stringify(sent.state.lab_queries)).not.toContain("captured_at");
    expect(calls[0]!.redirect).toBe("error");
    expect(calls[0]!.auth).toBe("Bearer or_test_key");
  });

  test("one incident per source per 60s: new rows inside the window fold in without reclassifying", async () => {
    let now = 1_000_000_000;
    const { calls, fetcher } = stubProvider("suspicious");
    const lc = new LogClassifier(opts(fetcher, () => now));

    await lc.ingest([row({ id: "q1", observed_at: now })]);
    now += 10_000;
    await lc.ingest([row({ id: "q2", observed_at: now })]);

    expect(calls).toHaveLength(1); // no reclassify flood
    const snap = lc.snapshot();
    expect(snap.incidents).toHaveLength(1);
    expect(snap.incidents[0]!.source_ids).toEqual(["q1", "q2"]);
  });

  test("after the window a new incident is opened and classified again", async () => {
    let now = 1_000_000_000;
    const { calls, fetcher } = stubProvider("suspicious");
    const lc = new LogClassifier(opts(fetcher, () => now));

    await lc.ingest([row({ id: "q1", observed_at: now })]);
    now += 61_000;
    await lc.ingest([row({ id: "q2", observed_at: now })]);

    expect(calls).toHaveLength(2);
    expect(lc.snapshot().incidents).toHaveLength(2);
  });

  test("duplicate ids are classified once; the same batch replayed adds nothing", async () => {
    const now = 1_000_000_000;
    const { calls, fetcher } = stubProvider("suspicious");
    const lc = new LogClassifier(opts(fetcher, () => now));

    await lc.ingest([row({ id: "q1", observed_at: now }), row({ id: "q1", observed_at: now })]);
    await lc.ingest([row({ id: "q1", observed_at: now })]);

    expect(calls).toHaveLength(1);
    expect(lc.snapshot().incidents[0]!.source_ids).toEqual(["q1"]);
  });

  test("benign-only and non-flagged rows create no incident and no model call", async () => {
    const now = 1_000_000_000;
    const { calls, fetcher } = stubProvider("benign");
    const lc = new LogClassifier(opts(fetcher, () => now));

    await lc.ingest([row({ id: "b1", observed_at: now, domain: "benign.lab.test", indicator: false })]);

    expect(calls).toHaveLength(0);
    expect(lc.snapshot()).toMatchObject({ status: "idle", incidents: [] });
  });

  test("stale rows (outside the 60s window) are not classified", async () => {
    const now = 1_000_000_000;
    const { calls, fetcher } = stubProvider("suspicious");
    const lc = new LogClassifier(opts(fetcher, () => now));

    await lc.ingest([row({ id: "old", observed_at: now - 120_000 })]);

    expect(calls).toHaveLength(0);
    expect(lc.snapshot().incidents).toHaveLength(0);
  });

  test("a flagged row with a foreign client is never classified or transmitted", async () => {
    const now = 1_000_000_000;
    const { calls, fetcher } = stubProvider("suspicious");
    const lc = new LogClassifier(opts(fetcher, () => now));

    await lc.ingest([row({ id: "x", observed_at: now, client: "10.0.0.5" })]);

    expect(calls).toHaveLength(0);
    expect(lc.snapshot().incidents).toHaveLength(0);
  });

  test("no key: incident is opened but degraded/unknown, no request, key never leaks", async () => {
    const now = 1_000_000_000;
    const { calls, fetcher } = stubProvider("suspicious");
    const lc = new LogClassifier(opts(fetcher, () => now, () => ""));

    await lc.ingest([row({ id: "q1", observed_at: now })]);
    const snap = lc.snapshot();

    expect(calls).toHaveLength(0);
    expect(snap.status).toBe("degraded");
    expect(snap.incidents[0]).toMatchObject({ category: "unknown", status: "degraded" });
    expect(snap.incidents[0]!.judgments[0]!.inference_status).toBe("failed");
  });

  test("a hosted failure degrades truthfully without throwing", async () => {
    const now = 1_000_000_000;
    const fetcher = (async () => new Response("nope", { status: 502 })) as unknown as typeof fetch;
    const lc = new LogClassifier(opts(fetcher, () => now));

    await lc.ingest([row({ id: "q1", observed_at: now })]);

    expect(lc.snapshot().incidents[0]).toMatchObject({ category: "unknown", status: "degraded" });
    expect(lc.snapshot().status).toBe("degraded");
  });

  test("snapshot is a deep copy; mutating it does not change retained state", async () => {
    const now = 1_000_000_000;
    const { fetcher } = stubProvider("suspicious");
    const lc = new LogClassifier(opts(fetcher, () => now));
    await lc.ingest([row({ id: "q1", observed_at: now })]);

    lc.snapshot().incidents[0]!.source_ids.push("tampered");
    expect(lc.snapshot().incidents[0]!.source_ids).toEqual(["q1"]);
  });
});
