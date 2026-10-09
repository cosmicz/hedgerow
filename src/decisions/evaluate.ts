import { baseline, Classifier, OpenRouterProvider, type Category, type DecisionInput, type DecisionModel, type Judgment } from "./index";

interface Case { id: string; expected: Category; input: DecisionInput }
function fixture(id:string, expected:Category, facts:DecisionInput["facts"], coverage:DecisionInput["coverage"]="fresh"): Case {
  return {id,expected,input:{evidence_revision:"a".repeat(64),evidence_ids:["b".repeat(64)],mode:"synthetic",coverage,facts}};
}
// Fixed task fixtures; these are not a representative home-network benchmark.
// Expected labels never enter the provider input or question schema.
export const heldOut: readonly Case[] = [
  fixture("one-indicator","suspicious",{queries:1,lab_indicator_match:true,novel_domain:false,benign_probe_ok:true}),
  fixture("repeated-indicator","suspicious",{queries:40,lab_indicator_match:true,novel_domain:true,benign_probe_ok:true}),
  fixture("known-benign","benign",{queries:8,lab_indicator_match:false,novel_domain:false,benign_probe_ok:true}),
  fixture("busy-benign","benign",{queries:400,lab_indicator_match:false,novel_domain:false,benign_probe_ok:true}),
  fixture("novel-only","unknown",{queries:2,lab_indicator_match:false,novel_domain:true,benign_probe_ok:true}),
  fixture("resolver-unhealthy","unknown",{queries:3,lab_indicator_match:true,novel_domain:false,benign_probe_ok:false}),
  fixture("empty","unknown",{queries:0,lab_indicator_match:false,novel_domain:false,benign_probe_ok:true}),
  fixture("stale-indicator","unknown",{queries:6,lab_indicator_match:true,novel_domain:false,benign_probe_ok:true},"stale"),
];
export async function evaluate(classify:(i:DecisionInput)=>Promise<Judgment>, cases:readonly Case[]=heldOut) {
  const rows = [];
  for (const c of cases) rows.push({id:c.id,expected:c.expected,judgment:await classify(c.input)});
  const times = rows.map(r=>r.judgment.latency_ms).sort((a,b)=>a-b);
  const percentile = (p:number)=>times.length ? times[Math.max(0,Math.ceil(p*times.length)-1)] : null;
  const requests = rows.filter(r=>r.judgment.inference_status !== "not-called");
  const assessed=rows.filter(r=>r.judgment.inference_status!=="failed");
  const succeeded=requests.filter(r=>r.judgment.inference_status==="succeeded");
  const hosted=succeeded.filter(r=>r.judgment.provenance==="hosted");
  const hostedCorrect=hosted.filter(r=>r.expected===r.judgment.category).length;
  const requestTimes=requests.map(r=>r.judgment.latency_ms).sort((a,b)=>a-b);
  const requestPercentile=(p:number)=>requestTimes.length ? requestTimes[Math.max(0,Math.ceil(p*requestTimes.length)-1)] : null;
  return {mode:"synthetic",scope:"Eight fixed lab-policy cases; not calibrated network security accuracy",rows,
    metrics:{cases:rows.length,correct:assessed.filter(r=>r.expected===r.judgment.category).length,
      inference_succeeded:succeeded.length,inference_failed:requests.length-succeeded.length,not_called:rows.length-requests.length,
      hosted_agreement:{correct:hostedCorrect,cases:hosted.length,rate:hosted.length?hostedCorrect/hosted.length:null},
      false_positives:assessed.filter(r=>r.expected==="benign"&&r.judgment.category==="suspicious").length,
      false_negatives:assessed.filter(r=>r.expected==="suspicious"&&r.judgment.category==="benign").length,
      abstentions:assessed.filter(r=>r.judgment.category==="unknown").length,
      suspicious_abstentions:assessed.filter(r=>r.expected==="suspicious"&&r.judgment.category==="unknown").length,
      p50_ms:percentile(.5),p95_ms:percentile(.95),
      provider_calls:requests.length,provider_p50_ms:requestPercentile(.5),provider_p95_ms:requestPercentile(.95),
      reported_cost_usd:requests.every(r=>r.judgment.cost_usd!==null) ? requests.reduce((n,r)=>n+r.judgment.cost_usd!,0) : null}};
}
if (import.meta.main) {
  const results: unknown[] = [{provider:"deterministic",result:await evaluate(async i=>({...baseline(i),cost_usd:0}))}];
  const enabled = process.env.RG_MODEL_LIVE === "1" && !!process.env.OPENROUTER_API_KEY;
  for (const model of ["typesafe/jev-1.13","cloudflare/clef"] as DecisionModel[]) {
    if (!enabled) {results.push({model,status:"not-run",reason:"Set local OPENROUTER_API_KEY and RG_MODEL_LIVE=1; synthetic-only bounded evaluation"});continue;}
    const c = new Classifier(new OpenRouterProvider(model,()=>process.env.OPENROUTER_API_KEY ?? ""));
    results.push({model,result:await evaluate(i=>c.classify(i))});
  }
  console.log(JSON.stringify({schema:1,results},null,2));
}
