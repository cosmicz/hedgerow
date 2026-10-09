// Automated, operator-authorized owned-lab take; keep record.ts running separately.
import { mkdirSync } from "node:fs";
if(process.env.RG_DEMO_RECORD_SEGMENTS!=="1")throw Error("Owned-lab recording opt-in required");
const started=Date.now(),marks:{stage:string;at:number}[]=[];
async function stage(name:string){
  marks.push({stage:name,at:Date.now()});
  const p=Bun.spawn([process.execPath,"tests/demo/record-segments.ts",name],{stdout:"inherit",stderr:"inherit",env:process.env});
  if(await p.exited)throw Error(`Recording stage failed: ${name}`);
}
const base="http://127.0.0.1:8787";
async function state(){return(await fetch(base+"/api/state")).json();}
async function command(name:string,digest:string){
  const {token}=await(await fetch(base+"/api/session")).json();
  const r=await fetch(base+"/api/"+name,{method:"POST",headers:{Origin:base,"Content-Type":"application/json","X-Hedgerow-CSRF":token},body:JSON.stringify({digest})});
  if(!r.ok)throw Error("Exact recording action failed");return r.json();
}
let digest:string|undefined;
try{
  await stage("logs");await stage("event");await stage("judgments");await stage("approval");
  const s=await state();digest=s.actions.filter((a:any)=>a.proposal.evidence_revision===s.finding.evidence_revision&&a.status==="proposed").at(-1)?.digest;
  if(!digest)throw Error("No exact current proposal");
  // Explicit automated test approval, not a claim that a human clicked in this take.
  await command("approve",digest);
  await stage("tools");await stage("recovery");digest=undefined;
  mkdirSync("private/demo",{recursive:true});
  const final=await state();
  await Bun.write(`private/demo/dns-recording-${started}.json`,JSON.stringify({started,finished:Date.now(),marks,approval:"operator-authorized automated test",state:final},null,2));
  console.log("PASS recorded DNS evidence -> hosted judgments -> approved agent -> measured recovery");
}finally{if(digest){const s=await state();if(s.actions.find((a:any)=>a.digest===digest)?.status==="active")await command("undo",digest);}}
