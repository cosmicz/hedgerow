import { expect } from "bun:test";
if(process.env.RG_ROUTER_LIVE!=="1")throw Error("Explicit owned-router integration-test opt-in required");
const base="http://127.0.0.1:8787", frames:unknown[]=[];
const {token}=await(await fetch(base+"/api/session")).json() as {token:string};
let failure:string|null=null;
async function call(name:string,input:unknown={}) {
  const r=await fetch(base+"/api/"+name,{method:"POST",signal:AbortSignal.timeout(120000),headers:{Origin:base,"Content-Type":"application/json","X-Hedgerow-CSRF":token},body:JSON.stringify(input)});
  const state:any=await r.json();frames.push({step:name,at:new Date().toISOString(),http:r.status,state});
  console.log(JSON.stringify({step:name,http:r.status,phase:state.router?.phase,attempts:state.router?.attempts,judgments:state.router?.judgments?.map((j:any)=>({model:j.model,category:j.category,inference:j.inference_status})),agent:state.router?.agent?.status}));
  if(!r.ok)throw Error("Router command failed: "+name);return state.router;
}
try {
  const s:any=await(await fetch(base+"/api/state")).json();expect(s.router?.phase).toBe("down");
  await call("router-prepare");const a=await call("router-attack");
  expect(a.attempts.map((x:any)=>x.outcome)).toEqual(["rejected","accepted"]);
  const c=await call("router-classify");expect(c.judgments.filter((j:any)=>j.provenance==="hosted"&&j.inference_status==="succeeded")).toHaveLength(2);
  const p=await call("router-propose");await call("router-approve",{digest:p.proposal.digest});
  const done=await call("router-execute",{digest:p.proposal.digest});
  expect(done.phase).toBe("rotated");expect(done.trace.attempts.map((x:any)=>x.outcome)).toEqual(["rejected","accepted","rejected","accepted"]);
  expect(done.agent.status).toBe("complete");expect(done.agent.explanation.citations.length).toBeGreaterThan(0);
  expect(done.agent.calls.some((c:any)=>c.name==="execute_approved"&&c.ok)).toBe(true);
}catch(error){failure=String(error);}
finally {
  const path=`private/demo/router-live-${Date.now()}.json`;
  const artifact={revision:Bun.spawnSync(["git","rev-parse","HEAD"]).stdout.toString().trim(),worktree_status:Bun.spawnSync(["git","status","--porcelain"]).stdout.toString(),approval:"operator-authorized automated integration test, not a human recording",mode:"vm-live",failure,frames};
  await Bun.write(path,JSON.stringify(artifact,null,2));
  console.log(JSON.stringify({path,sha256:new Bun.CryptoHasher("sha256").update(await Bun.file(path).arrayBuffer()).digest("hex"),failure}));
}
if(failure)process.exit(1);
