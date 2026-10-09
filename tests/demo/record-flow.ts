// Operator-authorized automated walkthrough; records real UI and real lab actions.
// Start record.ts first. This does not encode, speed up, or splice the recording.
export {};
if(process.env.RG_DEMO_RECORD_FLOW!=="1")throw Error("Explicit owned-lab recording opt-in required");
const pages:any[]=await(await fetch("http://127.0.0.1:9229/json/list")).json();
const page=pages.find(p=>p.type==="page"&&p.url==="http://127.0.0.1:8787/");
if(!page?.webSocketDebuggerUrl?.startsWith("ws://127.0.0.1:9229/"))throw Error("Dedicated demo page required");
const ws=new WebSocket(page.webSocketDebuggerUrl);await new Promise<void>(r=>ws.onopen=()=>r());
let id=0;const pending=new Map<number,(r:any)=>void>();
ws.onmessage=e=>{const m=JSON.parse(String(e.data));pending.get(m.id)?.(m);pending.delete(m.id);};
async function cdp(method:string,params:any={}){const n=++id;const promise=new Promise<any>(r=>pending.set(n,r));ws.send(JSON.stringify({id:n,method,params}));const m=await promise;if(m.error)throw Error("CDP failed");return m.result;}
async function evaluate(expression:string){const r=await cdp("Runtime.evaluate",{expression,awaitPromise:true,returnByValue:true});if(r.exceptionDetails)throw Error("Browser operation failed");return r.result.value;}
async function caption(text:string,selector:string){
  await evaluate(`(()=>{let n=document.getElementById('walkthrough-caption');if(!n){n=document.createElement('div');n.id='walkthrough-caption';n.style.cssText='position:fixed;bottom:14px;left:8%;right:8%;padding:14px 20px;background:#214D3B;color:white;font:18px/1.4 sans-serif;z-index:9999;border-radius:8px;pointer-events:none';document.body.append(n);}n.textContent=${JSON.stringify(text)};document.querySelector(${JSON.stringify(selector)})?.scrollIntoView({block:'start',behavior:'instant'});})()`);
  console.log(text);
}
async function command(name:string,digest?:string){await evaluate(`run(${JSON.stringify(name)},${JSON.stringify(digest?{digest}:{})})`);return evaluate("JSON.parse(JSON.stringify(state))");}
const hold=(ms:number)=>Bun.sleep(ms);
let dnsDigest:string|undefined;
try{
  await cdp("Runtime.enable");
  await caption("Hedgerow: a household-security appliance prototype. Automated live walkthrough; owned containers on this Mac, not a consumer-router compatibility claim.","header");await hold(8000);
  await command("router-prepare");
  await caption("First, a controlled attack: try one deliberately seeded lab credential. No guessing, scanning, or nearby network traffic.","#router-title");await hold(4000);
  let s=await command("router-attack");if(s.router.phase!=="attacked")throw Error("Attack measurement failed");await hold(6000);
  await caption("Jev and Clef assess only redacted authentication facts. Their judgments cannot authorize a change.","#router-title");
  s=await command("router-classify");if(s.router.judgments.filter((j:any)=>j.inference_status==="succeeded").length!==2)throw Error("Hosted router judgments unavailable");await hold(7000);
  s=await command("router-propose");const digest=s.router.proposal.digest;
  await caption("The owner reviews this exact password change. This automated test exercises the same explicit approval boundary shown in the UI.","#router");await hold(7000);
  await command("router-approve",digest);
  await caption("OpenAI can execute only the approved proposal. Independent login checks—not the explanation—determine whether it worked.","#router");
  s=await command("router-execute",digest);if(s.router.phase!=="rotated"||s.router.agent?.status!=="complete")throw Error("Router rotation not fully verified");
  await caption("Verified in this live lab: the old login is rejected, the replacement works. OpenAI explains the timestamped traces and cites its evidence.","#router .measured");await hold(10000);
  await caption("Next, monitoring: our owned client looks up a configured DNS test indicator. This is a controlled signal, not detected malware.","#incident-title");
  await command("observe");await command("classify");await hold(5000);
  s=await command("propose");dnsDigest=s.actions.filter((a:any)=>a.proposal.evidence_revision===s.finding.evidence_revision).at(-1).digest;
  await caption("A narrow repair: temporarily deny one test name for one lab client group. Other clients and existing connections are outside this protection.","#approval");await hold(6000);
  await command("approve",dnsDigest);s=await command("execute",dnsDigest);
  const action=s.actions.find((a:any)=>a.digest===dnsDigest);if(action.status!=="active"||action.verification.target!=="blocked"||action.verification.benign!=="resolved")throw Error("DNS verification failed");
  await caption("Measured result: the test name is blocked; the benign lookup still resolves. The model explanation is separate and trace-cited.","#verification");await hold(9000);
  await caption("Senso supplies cited public guidance about limits. It does not receive household traffic or grant action authority.","#guidance");
  await evaluate("document.querySelector('#guidance details').open=true");await hold(7000);
  await caption("ClickHouse retains observations; MongoDB mirrors the action audit. Semgrep records a real source scan. The local journal remains authoritative.","#sponsors-title");await hold(8000);
  s=await command("undo",dnsDigest);if(s.actions.find((a:any)=>a.digest===dnsDigest)?.verification.target!=="resolved")throw Error("Undo not verified");dnsDigest=undefined;
  await caption("Recovery verified: both DNS lookups resolve again. Audit history remains. Router compatibility, whole-network visibility, and Wi-Fi protection are not claimed.","#verification");await hold(10000);
  console.log("PASS continuous automated walkthrough");
}finally{
  if(dnsDigest)await command("undo",dnsDigest).catch(()=>{});
  ws.close();
}
