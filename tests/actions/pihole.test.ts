import { expect, test } from "bun:test";
import { PiholeAdapter } from "../../src/actions/pihole";

test("Pi-hole uses local session headers and exact scoped rules; HTTP success is not semantic success", async () => {
  const calls: { url: string; init?: RequestInit }[] = [];
  let fail = false;
  const adapter = new PiholeAdapter({ base_url: "http://127.0.0.1:8053/api", password: () => "private-secret",
    domain: "flagged.lab.test", group_id: 1, fetcher: async (url, init) => {
      calls.push({ url: String(url), init });
      if (String(url).endsWith("/auth")) return Response.json({ session: {valid: true, sid: "private-session"} });
      if (init?.method === "GET") return Response.json({ domains: [] });
      return Response.json({ processed: { success: fail ? [] : [{item: "flagged.lab.test"}], errors: fail ? [{error: "private-secret"}] : [] } });
    } });
  expect(await adapter.read("flagged.lab.test")).toBeNull();
  const rule = { domain: "flagged.lab.test", groups: [1], enabled: true, comment: `router-guard:${"a".repeat(64)}` };
  await adapter.create(rule);
  expect(calls[0].url).toBe("http://127.0.0.1:8053/api/auth");
  expect(new Headers(calls[1].init?.headers).get("X-FTL-SID")).toBe("private-session");
  expect(calls.every(x => !x.url.includes("private"))).toBe(true);
  await expect(adapter.create({...rule, groups: [0]})).rejects.toThrow();
  await expect(adapter.remove("elsewhere.example")).rejects.toThrow();
  fail = true;
  await expect(adapter.create(rule)).rejects.toThrow("Pi-hole rejected exact rule");
});

test("only explicit loopback lab endpoint allowed; redirects and malformed responses fail closed", async () => {
  const opts = { password: () => "secret", domain: "flagged.lab.test", group_id: 1 };
  for (const base_url of ["http://router.local/api", "https://example.com/api", "http://127.0.0.1:8053/other", "http://user:pass@127.0.0.1/api"]) {
    expect(() => new PiholeAdapter({ ...opts, base_url })).toThrow();
  }
  const adapter = new PiholeAdapter({ ...opts, base_url: "http://127.0.0.1:8053/api", fetcher: async (_url, init) => {
    expect(init?.redirect).toBe("error");
    return Response.json({ session: {valid: false, sid: "unusable"} });
  } });
  await expect(adapter.read("flagged.lab.test")).rejects.toThrow();
});
