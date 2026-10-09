import { randomBytes } from "node:crypto";
import { mkdirSync, openSync, closeSync, unlinkSync, readFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { PiholeAdapter, SqliteLedger } from "../actions";
import { createLabVerifier } from "../actions/lab-verifier";
import { Classifier, OpenRouterProvider } from "../decisions";
import { OpenRouterAgentProvider } from "../agent";
import { DemoController } from "./controller";
import { pollQueryEvidence, fetchOwnedQueries } from "./evidence";
import { createDemoHandler } from "./http";
import { SponsorBridge, runSemgrep, SensoGuidance } from "../adapters/sponsors";
import { DemoSponsors } from "./sponsors";
import { DemoGuidance } from "./guidance";
import { DemoRouter } from "./router";
import { createRouterLabController } from "../router/controller";
import { BunRouterRunner, systemClock } from "../router/runner";
import { classifyRouter } from "../decisions/router";
import { CapturedLogs } from "./logs";
import { DemoChat } from "./chat";
import { LogClassifier, type Incident } from "./log-classifier";

const lab = process.env.RG_LAB_DIR;
const group = Number(process.env.RG_LAB_GROUP);
if (!lab || !Number.isSafeInteger(group) || group < 1) throw new Error("Set RG_LAB_DIR and RG_LAB_GROUP for the reviewed isolated lab");
const password = readFileSync(join(lab, ".env"), "utf8").match(/^PIHOLE_API_PASSWORD=(.+)$/m)?.[1]?.replace(/^['"]|['"]$/g, "");
if (!password) throw new Error("Dedicated lab credentials unavailable");
const privateDir = resolve("private/demo"); mkdirSync(privateDir, { recursive: true, mode: 0o700 });
const lockPath = join(privateDir, "server.lock");
// Never guess whether a previous process is dead: operator verifies before removing a stale lock.
const lock = openSync(lockPath, "wx", 0o600); closeSync(lock);
process.on("exit", () => { try { unlinkSync(lockPath); } catch {} });
const ledger = new SqliteLedger(join(privateDir, "actions.sqlite"));
const logs = new CapturedLogs(join(privateDir, "captured-logs.sqlite"), () => fetchOwnedQueries(password, Date.now()-60_000, true));
const logModels = ["typesafe/jev-1.13", "cloudflare/clef"].map(model=>new LogClassifier({model:model as "typesafe/jev-1.13"|"cloudflare/clef"}));
const incidents = {snapshot(){
  const groups=new Map<string,Incident>();
  for(const model of logModels)for(const incident of model.snapshot().incidents){
    const key=incident.source_ids[0]!;
    const existing=groups.get(key);
    if(existing){
      existing.judgments.push(...incident.judgments);
      for(const id of incident.source_ids)if(!existing.source_ids.includes(id))existing.source_ids.push(id);
      existing.category=existing.judgments.some(j=>j.category==="suspicious")?"suspicious":existing.judgments.every(j=>j.category==="benign")?"benign":"unknown";
      if(incident.status==="degraded")existing.status="degraded";
    }else groups.set(key,incident);
  }
  return {status:logModels.every(m=>m.snapshot().status==="live")?"live":"pending",incidents:[...groups.values()].sort((a,b)=>b.started_at-a.started_at)};
}};
const sponsorBridge = await SponsorBridge.open({
  clickhouse: process.env.RG_CLICKHOUSE_URL ? { url: process.env.RG_CLICKHOUSE_URL } : undefined,
  mongodb: process.env.RG_MONGO_URI ? { uri: process.env.RG_MONGO_URI } : undefined,
});
if (process.env.RG_SEMGREP_SCAN === "1") {
  await sponsorBridge.recordSecurityScan(await runSemgrep({ cwd: process.cwd(), targets: ["src"] }));
}
const adapter = new PiholeAdapter({ base_url: "http://127.0.0.1:8053/api", password: () => password, domain: "flagged.lab.test", group_id: group });
const guidance = new DemoGuidance(SensoGuidance.fromEnv());
guidance.start();
const router = process.env.RG_ROUTER_LAB === "1" ? new DemoRouter({
  backend: createRouterLabController({ runner: new BunRouterRunner(), now: systemClock, privateDirectory: join(privateDir, "router") }),
  now: Date.now, agent: new OpenRouterAgentProvider(() => process.env.OPENROUTER_API_KEY ?? ""),
  classify: (attempts, revision, now) => classifyRouter(attempts, `sha256:${revision}`, now, () => process.env.OPENROUTER_API_KEY ?? ""),
}) : undefined;
const controller = new DemoController({ ledger, adapter, group, now: Date.now, verify: createLabVerifier(lab),
  sponsors: new DemoSponsors(sponsorBridge), guidance, router, logs, chat: new DemoChat(), incidents,
  deployment: process.env.RG_DEPLOYMENT === "pi-hybrid" ? "pi-hybrid" : "mac-lab",
  collect: async from => pollQueryEvidence(() => fetchOwnedQueries(password, from), from),
  classifiers: ["typesafe/jev-1.13", "cloudflare/clef"].map(model => new Classifier(new OpenRouterProvider(model as "typesafe/jev-1.13" | "cloudflare/clef", () => process.env.OPENROUTER_API_KEY ?? ""))),
  agent: new OpenRouterAgentProvider(() => process.env.OPENROUTER_API_KEY ?? ""),
});
await controller.reconcile(true);
const assets: Record<string, { body: string; type: string }> = {};
for (const [route, file, type] of [["/", "index.html", "text/html; charset=utf-8"], ["/app.js", "app.js", "text/javascript; charset=utf-8"], ["/style.css", "style.css", "text/css; charset=utf-8"]]) {
  assets[route!] = { body: await Bun.file(join(import.meta.dir, "public", file!)).text(), type: type! };
}
// A Pi reverse-forward may use a different Mac loopback port; the exact origin remains enforced.
const origin = process.env.RG_UI_ORIGIN ?? "http://127.0.0.1:8787";
const handler = createDemoHandler({ origin, token: randomBytes(32).toString("hex"), assets,
  state: () => controller.state(), command: (name, input) => controller.command(name, input) });
const server = Bun.serve({ hostname: "127.0.0.1", port: 8787, idleTimeout: 120, maxRequestBodySize: 4096, fetch: handler });
const timer = setInterval(() => { void controller.reconcile().catch(() => {}); }, 1000);
let collecting=false;
async function collectLogs(){
  if(collecting)return;
  collecting=true;
  try{await logs.poll();const rows=logs.snapshot().rows;await Promise.all(logModels.map(m=>m.ingest(rows)));}
  catch{/* Collection/model status stays visible; neither grants action authority. */}
  finally{collecting=false;}
}
void collectLogs();
const logTimer = setInterval(() => { void collectLogs(); }, 2000);
process.on("SIGINT", async () => { clearInterval(timer); clearInterval(logTimer); server.stop(); await sponsorBridge.close(); ledger.close(); process.exit(0); });
console.log(`Hedgerow local demo: ${origin}. Isolated container lab only. Human approval required for changes.`);
