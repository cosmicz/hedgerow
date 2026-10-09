import { expect, test } from "bun:test";
import { createDemoHandler } from "../../src/demo/http";

const origin = "http://127.0.0.1:8787";
const token = "c".repeat(64);
test("chat accepts only bounded text in an authenticated local request",async()=>{
  const {handler,post,commands}=fixture();
  for(const input of [{},{message:""},{message:"x".repeat(1001)},{message:"hello",approve:true}])expect((await handler(post("/api/chat",input))).status).toBe(400);
  expect((await handler(post("/api/chat",{message:"What happened?"},{Origin:"https://evil.test"}))).status).toBe(403);
  expect(commands).toHaveLength(0);
  expect((await handler(post("/api/chat",{message:"What happened?"}))).status).toBe(200);
  expect(commands).toEqual([{name:"chat",input:{message:"What happened?"}}]);
});
test("Pi tunnel accepts only its configured loopback origin", async () => {
  const forwarded = "http://127.0.0.1:8788";
  const handler = createDemoHandler({origin:forwarded,token,assets:{},state:()=>({}),command:async()=>({})});
  expect((await handler(new Request(forwarded+"/api/state",{headers:{Host:"127.0.0.1:8788"}}))).status).toBe(200);
  expect((await handler(new Request(forwarded+"/api/state",{headers:{Host:"127.0.0.1:8787"}}))).status).toBe(403);
  expect(()=>createDemoHandler({origin:"http://10.77.1.2:8787",token,assets:{},state:()=>({}),command:async()=>({})})).toThrow();
});
test("router commands retain exact human-session and digest boundary", async () => {
  const { handler, post, commands } = fixture();
  expect((await handler(post("/api/router-approve", {}))).status).toBe(400);
  expect((await handler(post("/api/router-approve", {digest:"a".repeat(64)}, {Origin:"https://evil.test"}))).status).toBe(403);
  expect(commands).toHaveLength(0);
  expect((await handler(post("/api/router-prepare"))).status).toBe(200);
  expect((await handler(post("/api/router-approve", {digest:"a".repeat(64)}))).status).toBe(200);
  expect(commands).toHaveLength(2);
});
function fixture() {
  const commands: unknown[] = [];
  const handler = createDemoHandler({ origin, token, assets: {},
    state: () => ({ status: "idle" }),
    command: async (name, input) => { commands.push({ name, input }); return { status: "changed" }; } });
  const post = (path: string, body: unknown = {}, headers: Record<string, string> = {}) => new Request(origin + path, {
    method: "POST", headers: { Host: "127.0.0.1:8787", Origin: origin, "Content-Type": "application/json", "X-Hedgerow-CSRF": token, ...headers },
    body: JSON.stringify(body),
  });
  return { handler, commands, post };
}
test("HTTP boundary changes state only for exact local authenticated command", async () => {
  const { handler, commands, post } = fixture();
  const attacks: Record<string, string>[] = [{ Origin: "https://evil.test" }, { Host: "evil.test" }, { "X-Hedgerow-CSRF": "wrong" }, { "Sec-Fetch-Site": "cross-site" }];
  for (const headers of attacks) {
    expect((await handler(post("/api/observe", {}, headers))).status).toBe(403);
  }
  expect(commands).toHaveLength(0);
  expect((await handler(post("/api/observe"))).status).toBe(200);
  expect(commands).toEqual([{ name: "observe", input: {} }]);
});
test("commands reject missing, extra or malformed approval identifiers and large bodies", async () => {
  const { handler, commands, post } = fixture();
  for (const body of [{}, { digest: "bad" }, { digest: ["a".repeat(64)] }, { digest: "a".repeat(64), approved: true }, []]) {
    expect((await handler(post("/api/approve", body))).status).toBe(400);
  }
  expect((await handler(post("/api/observe", { payload: "x".repeat(5000) }))).status).toBe(413);
  expect((await handler(post("/api/observe", {}, { "Content-Type": "text/plain" }))).status).toBe(415);
  expect((await handler(post("/api/shell"))).status).toBe(404);
  expect(commands).toHaveLength(0);
  expect((await handler(post("/api/approve", { digest: "a".repeat(64) }))).status).toBe(200);
  expect(commands).toHaveLength(1);
});
test("GET cannot mutate; API has no CORS and cannot be read through a rebound Host", async () => {
  const { handler, commands } = fixture();
  expect((await handler(new Request(origin + "/api/undo", { headers: { Host: "127.0.0.1:8787" } }))).status).toBe(404);
  expect((await handler(new Request(origin + "/api/state", { headers: { Host: "evil.test" } }))).status).toBe(403);
  const response = await handler(new Request(origin + "/api/state", { headers: { Host: "127.0.0.1:8787" } }));
  expect(await response.json()).toEqual({ status: "idle" });
  expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
  expect(response.headers.get("Cache-Control")).toBe("no-store");
  expect(commands).toHaveLength(0);
});
test("concurrent commands fail closed and internal errors are redacted", async () => {
  let release!: () => void;
  let calls = 0;
  const { post } = fixture();
  const handler = createDemoHandler({ origin, token, assets: {}, state: () => ({}), command: async () => {
    calls++;
    await new Promise<void>(resolve => { release = resolve; });
    throw new Error("SECRET-password");
  } });
  const first = handler(post("/api/observe"));
  while (!release) await Bun.sleep(1);
  expect((await handler(post("/api/observe"))).status).toBe(409);
  release();
  const response = await first;
  expect(response.status).toBe(409);
  expect(await response.text()).not.toContain("SECRET");
  expect(calls).toBe(1);
});
