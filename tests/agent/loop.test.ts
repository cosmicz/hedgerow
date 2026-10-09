import { expect, test } from "bun:test";
import { AgentLoop, type AgentPorts, type AgentProvider, type Trace } from "../../src/agent";

const digest = "a".repeat(64), revision = "b".repeat(64);
const evidence: Trace = {id:"trace:1",at:1,kind:"observation",mode:"synthetic",summary:"Configured lab indicator observed",evidence_ids:["observation:"+"c".repeat(64)]};
function setup(outputs: any[]) {
  let mutations = 0; let approved = false; let calls = 0;
  const ports: AgentPorts = {revision:()=>revision,traces:()=>[evidence],finding:()=>"finding:"+revision,
    propose:async()=>({digest,status:"proposed"}),
    execute:async id=>{if(id!==digest||!approved)throw new Error("SECRET unauthorized");mutations++;return {digest,status:"active",verification:{target:"blocked",benign:"resolved",mode:"synthetic",checked_at:2}};},
    status:async()=>({digest,status:approved?"approved":"proposed"})};
  const provider:AgentProvider = {model:"fixture",provenance:"fake",respond:async()=>{calls++;return outputs.shift() ?? {output:[]};}};
  const loop = new AgentLoop(ports,provider);
  return {loop,approve:()=>{approved=true;},mutations:()=>mutations,calls:()=>calls};
}
const tool = (name:string,args:unknown,id="c1")=>({type:"function_call",name,arguments:JSON.stringify(args),call_id:id});
const final = (citations=["trace:1"])=>({output:[{type:"message",content:[{type:"output_text",text:JSON.stringify({text:"The lab observation needs review.",citations})}]}]});
test("model proposes then waits; no tool can grant approval",async()=>{
  const s=setup([{output:[tool("propose_dns_deny",{evidence_revision:revision})]},final()]);
  const r=await s.loop.run({evidence_revision:revision,proposal_digests:[],judgment:"suspicious"});
  expect(r.proposals).toEqual([digest]);expect(s.mutations()).toBe(0);expect(r.explanation?.citations).toEqual(["trace:1"]);
});
function permissive(outputs:any[],finding:string|null="finding:"+revision) {
  const counts={propose:0,execute:0,status:0};let current=revision;
  const loop=new AgentLoop({revision:()=>current,traces:()=>[evidence],finding:()=>finding,
    propose:async()=>{counts.propose++;return {digest,status:"proposed"};},
    execute:async()=>{counts.execute++;return {digest,status:"active"};},
    status:async()=>{counts.status++;return {digest,status:"approved"};}},
    {model:"fixture",provenance:"fake",respond:async()=>outputs.shift()??final()});
  return {loop,counts,changeRevision:()=>{current="e".repeat(64);}};
}
test("proposal requires deterministic finding even when model says suspicious; benign judgment cannot erase finding",async()=>{
  for(const [finding,judgment,expected] of [[null,"suspicious",0],["finding:"+revision,"benign",1]] as const) {
    const s=permissive([{output:[tool("propose_dns_deny",{evidence_revision:revision})]},final()],finding);
    await s.loop.run({evidence_revision:revision,proposal_digests:[],judgment});
    expect(s.counts.propose).toBe(expected);
  }
});
test("loop itself rejects unknown digests, extra execute args and stale proposal revision",async()=>{
  for(const call of [tool("execute_approved",{digest:"d".repeat(64)}),tool("execute_approved",{digest,extra:true}),
    tool("propose_dns_deny",{evidence_revision:"d".repeat(64)})]) {
    const s=permissive([{output:[call]},final()]);
    await s.loop.run({evidence_revision:revision,proposal_digests:[digest],judgment:"suspicious"});
    expect(s.counts).toEqual({propose:0,execute:0,status:0});
  }
});
test("call ID guard independently rejects duplicate read calls",async()=>{
  const s=permissive([{output:[tool("get_action_status",{digest})]},{output:[tool("get_action_status",{digest})]},final()]);
  await s.loop.run({evidence_revision:revision,proposal_digests:[digest],judgment:"unknown"});
  expect(s.counts.status).toBe(1);
});
test("unknown, unapproved, extra-field and cross-run tool calls cannot mutate",async()=>{
  for(const t of [tool("approve",{digest}),tool("execute_approved",{digest:"d".repeat(64)}),
    tool("execute_approved",{digest,approved:true}),tool("execute_approved",{digest})]) {
    const s=setup([{output:[t]},final()]);
    const r=await s.loop.run({evidence_revision:revision,proposal_digests:[digest],judgment:"suspicious"});
    expect(s.mutations()).toBe(0);expect(r.calls[0]?.ok).toBe(false);
    expect(JSON.stringify(r)).not.toContain("SECRET");
  }
});
test("approved tool mutates once; duplicate call IDs never repeat execution",async()=>{
  const s=setup([{output:[tool("execute_approved",{digest})]},
    {output:[tool("execute_approved",{digest})]},final()]);s.approve();
  const r=await s.loop.run({evidence_revision:revision,proposal_digests:[digest],judgment:"suspicious"});
  expect(s.mutations()).toBe(1);expect(r.calls[0]?.result?.status).toBe("active");
  expect(r.calls[1]?.ok).toBe(false);
});
test("different call IDs cannot replay the same mutation within a run",async()=>{
  const s=setup([{output:[tool("execute_approved",{digest},"first")]},
    {output:[tool("execute_approved",{digest},"second")]},final()]);s.approve();
  const r=await s.loop.run({evidence_revision:revision,proposal_digests:[digest],judgment:"suspicious"});
  expect(s.mutations()).toBe(1);expect(r.calls[1]?.ok).toBe(false);
});
test("failed narration preserves measured mutation without replay or invented explanation",async()=>{
  const s=setup([{output:[tool("execute_approved",{digest})]},null]);s.approve();
  const r=await s.loop.run({evidence_revision:revision,proposal_digests:[digest],judgment:"suspicious"});
  expect(s.mutations()).toBe(1);expect(r.status).toBe("degraded");
  expect(r.calls[0]?.result?.verification?.target).toBe("blocked");
  expect(r.explanation).toBeNull();expect(s.calls()).toBe(2);
});
test("fabricated citations are rejected and missing provider never fabricates mitigation",async()=>{
  const s=setup([final(["trace:invented"])]);
  const r=await s.loop.run({evidence_revision:revision,proposal_digests:[],judgment:"unknown"});
  expect(r.explanation).toBeNull();expect(r.status).toBe("degraded");expect(s.mutations()).toBe(0);
  expect(r.provenance).toBe("fake");
});
test("stale evidence rejects tools and bounded loops stop",async()=>{
  const s=setup(Array.from({length:20},(_,n)=>({output:[tool("get_trace",{},`c${n}`)]})));
  const r=await s.loop.run({evidence_revision:revision,proposal_digests:[],judgment:"unknown"});
  expect(s.calls()).toBeLessThanOrEqual(4);expect(r.status).toBe("degraded");
  const t=setup([{output:[tool("propose_dns_deny",{evidence_revision:revision})]}]);
  expect((await t.loop.run({evidence_revision:"e".repeat(64),proposal_digests:[],judgment:"suspicious"})).status).toBe("degraded");
  expect(t.calls()).toBe(0);expect(t.mutations()).toBe(0);
});
