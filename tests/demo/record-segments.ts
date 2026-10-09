export {};
// Captures individual real UI stages through the dedicated demo CDP page.
// Start tests/demo/record.ts separately. This script neither encodes nor fabricates UI data.
if (process.env.RG_DEMO_RECORD_SEGMENTS !== "1") throw new Error("set RG_DEMO_RECORD_SEGMENTS=1 for an owned demo recording");

const stage = Bun.argv[2];
const stages = ["logs", "event", "judgments", "approval", "tools", "recovery"] as const;
if (!stages.includes(stage as typeof stages[number])) throw new Error(`usage: record-segments.ts <${stages.join("|")}>`);

const pages: any[] = await (await fetch("http://127.0.0.1:9229/json/list")).json();
const page = pages.find((entry) => entry.type === "page" && entry.url === "http://127.0.0.1:8787/");
if (!page?.webSocketDebuggerUrl?.startsWith("ws://127.0.0.1:9229/")) throw new Error("dedicated demo CDP page is required");
const socket = new WebSocket(page.webSocketDebuggerUrl);
await new Promise<void>((resolve) => socket.addEventListener("open", () => resolve(), { once: true }));
let id = 0;
const pending = new Map<number, (message: any) => void>();
socket.onmessage = (event) => { const message = JSON.parse(String(event.data)); pending.get(message.id)?.(message); pending.delete(message.id); };
async function cdp(method: string, params: Record<string, unknown> = {}) { const requestId = ++id; const result = new Promise<any>((resolve) => pending.set(requestId, resolve)); socket.send(JSON.stringify({ id: requestId, method, params })); const message = await result; if (message.error) throw new Error(`CDP ${method} failed`); return message.result; }
async function evaluate(expression: string) { const result = await cdp("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }); if (result.exceptionDetails) throw new Error("real UI operation failed"); return result.result.value; }
async function command(name: string, digest?: string) { await evaluate(`run(${JSON.stringify(name)},${JSON.stringify(digest ? { digest } : {})})`); return evaluate("JSON.parse(JSON.stringify(state))"); }
async function caption(text: string, selector: string) { await evaluate(`(()=>{let n=document.getElementById('recording-stage-caption');if(!n){n=document.createElement('div');n.id='recording-stage-caption';n.style.cssText='position:fixed;bottom:14px;left:8%;right:8%;z-index:9999;padding:12px;background:#214D3B;color:#fff;font:16px sans-serif;border-radius:8px;pointer-events:none';document.body.append(n)}n.textContent=${JSON.stringify(text)};document.querySelector(${JSON.stringify(selector)})?.scrollIntoView({block:'start',behavior:'instant'})})()`); }

try {
  await cdp("Runtime.enable");
  await evaluate("refresh()");
  if (stage === "logs") {
    await caption("Captured DNS log history from the active owned-lab demo. Rows shown are measured observations.", "#live-logs");
  } else if (stage === "event") {
    await caption("Controlled DNS test indicator observed in the owned lab. The selected row is captured evidence, not synthetic video text.", "#live-logs");
    let state = await command("observe");
    const refs=state.evidence?.observations.filter((o:any)=>o.kind==="dns_query").map((o:any)=>o.evidence_ref)??[];
    for(let i=0;i<8&&!state.logs?.rows?.some((r:any)=>refs.includes(r.id));i++){await Bun.sleep(500);await evaluate("refresh()");state=await evaluate("JSON.parse(JSON.stringify(state))");}
    if(!refs.length||!state.logs?.rows?.some((r:any)=>refs.includes(r.id)))throw new Error("no captured DNS row matches this incident");
    await evaluate(`document.querySelector('#live-logs')?.scrollIntoView({block:'start',behavior:'instant'})`);
  } else if (stage === "judgments") {
    const state = await command("classify"); if (state.judgments?.filter((j:any)=>j.provenance==="hosted"&&j.inference_status==="succeeded").length!==2) throw new Error("both hosted DNS judgments must succeed");
    await caption("Jev and Clef assess the captured DNS evidence. Their responses cannot authorize any change.", "#judgments"); await Bun.sleep(2_000);
    await caption("Response history records the hosted judgment exchange alongside its evidence boundary.", "#response-history");
  } else if (stage === "approval") {
    const state = await command("propose"); const action = state.actions?.filter((entry: any) => entry.proposal?.evidence_revision === state.finding?.evidence_revision).at(-1); if (!action?.digest) throw new Error("no proposal binds the current DNS evidence revision");
    await caption("The proposed DNS action is bound to this exact captured evidence revision. Operator approval is a separate boundary.", "#approval");
  } else if (stage === "tools") {
    const state = await evaluate("JSON.parse(JSON.stringify(state))"); const action = state.actions?.filter((entry: any) => entry.proposal?.evidence_revision === state.finding?.evidence_revision && entry.status === 'approved').at(-1); if (!action?.digest) throw new Error("an exact approved DNS proposal must already be visible");
    await caption("OpenAI receives only the exact approved DNS action. Independent verification determines the result.", "#response-history");
    const next = await command("execute", action.digest); const active = next.actions?.find((entry: any) => entry.digest === action.digest); if (active?.status !== "active" || active?.verification?.target !== "blocked" || active?.verification?.benign !== "resolved") throw new Error("DNS action verification failed");
    await caption("Measured outcome: the test indicator is blocked and the benign DNS lookup still resolves.", "#verification");
  } else {
    const state = await evaluate("JSON.parse(JSON.stringify(state))"); const action = state.actions?.filter((entry: any) => entry.proposal?.evidence_revision === state.finding?.evidence_revision && entry.status === 'active').at(-1); if (!action?.digest) throw new Error("an active DNS action is required for recovery");
    const next = await command("undo", action.digest); const undone = next.actions?.find((entry: any) => entry.digest === action.digest); if (undone?.verification?.target !== "resolved" || undone?.verification?.benign !== "resolved") throw new Error("DNS recovery verification failed");
    await caption("Recovery verified: both DNS lookups resolve again; the audit history remains.", "#verification");
  }
  await Bun.sleep(6_000);
  console.log(`PASS real UI recording stage=${stage}`);
} finally { socket.close(); }
