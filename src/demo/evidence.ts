import { replay, type ReplayResult } from "../replay/evaluate";
import type { ReplayContext } from "../replay/normalize";

export const scope = "lab:rg-lab";
export const target = "flagged.lab.test";
export const source = "pihole-owned-client";
/** Pi-hole exposes some completed queries after the probe returns. Retry reads only. */
export async function pollQueryEvidence(read: () => Promise<unknown>, from: number, now = Date.now,
  sleep: (ms: number) => Promise<unknown> = Bun.sleep): Promise<ReplayResult> {
  for (let attempt = 0; ; attempt++) {
    const result = collectQueryEvidence(await read(), from, now());
    if (result.findings.some(f => f.rule_id === "flagged-test-domain") || attempt === 5) return result;
    await sleep(400);
  }
}
/** Adapt the running Pi-hole v6 /queries schema, not the authored fixture schema. */
export function collectQueryEvidence(data: unknown, from: number, now: number): ReplayResult {
  if (!Number.isSafeInteger(from) || !Number.isSafeInteger(now) || now < from || now - from > 60_000) throw new Error("Invalid collection window");
  const rows = (data as any)?.queries;
  if (!Array.isArray(rows) || rows.length > 100) throw new Error("Query evidence unavailable");
  const at = new Date(now).toISOString();
  const common = { received_at: at, source_id: source, network_scope: scope, mode: "vm-live" };
  const fixtures: unknown[] = [{ ...common, event_id: `collector-${now}`, observed_at: at,
    evidence_ref: "pihole:queries:owned-client", kind: "collector_status", payload: { available: true, check: "api-reachable", generated_by: "application" } }];
  for (const row of rows) {
    if (!row || !Number.isSafeInteger(row.id) || row.id < 0 || typeof row.time !== "number" || !Number.isFinite(row.time) ||
      typeof row.domain !== "string" || typeof row.client?.ip !== "string") throw new Error("Malformed query evidence");
    const observed = Math.round(row.time * 1000);
    if (row.domain !== target || row.client.ip !== "10.77.0.100" || row.type !== "A" || observed < from || observed > now) continue;
    // Closed projection deliberately drops client names, upstreams and arbitrary response text.
    fixtures.push({ ...common, event_id: `query-${row.id}`, observed_at: new Date(observed).toISOString(),
      evidence_ref: `pihole:query:${row.id}`, kind: "dns_query", payload: {
        domain: target, client: "10.77.0.100", query_type: "A",
        status: ["CACHE", "FORWARDED", "GRAVITY", "DENYLIST", "SPECIAL_DOMAIN"].includes(row.status) ? row.status : "OTHER",
        reply: row.reply?.type === "IP" ? "IP" : "OTHER",
      } });
  }
  const context: ReplayContext = { evaluated_at: at,
    expected_collectors: [{ source_id: source, network_scope: scope, mode: "vm-live" }],
    max_age_ms: { dns_query: 60_000, collector_status: 60_000, service_status: 60_000, wifi_posture: 60_000 } };
  return replay(fixtures, context);
}

/** Fixed loopback endpoint and owned query filter; credentials remain server-side. */
export async function fetchOwnedQueries(password: string, from: number, history = false): Promise<unknown> {
  let sid: string | null = null;
  const base = "http://127.0.0.1:8053/api";
  const request = async (path: string, method = "GET", body?: unknown) => {
    const response = await fetch(base + path, { method, redirect: "error", signal: AbortSignal.timeout(5000),
      headers: { "Content-Type": "application/json", ...(sid ? { "X-FTL-SID": sid } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body) });
    if (!response.ok) throw new Error("Query collection unavailable");
    return response.status === 204 ? null : response.json();
  };
  try {
    const auth: any = await request("/auth", "POST", { password });
    if (auth?.session?.valid !== true || typeof auth.session.sid !== "string" || !auth.session.sid) throw new Error("Query authentication unavailable");
    sid = auth.session.sid;
    return await request(`/queries?${history ? "" : "domain=flagged.lab.test&"}client_ip=10.77.0.100&type=A&length=100&from=${Math.floor(from / 1000)}`);
  } finally { if (sid) { try { await request("/auth", "DELETE"); } catch { /* No mutation was authorized by this collector. */ } } }
}
