import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AgentLoop, OpenRouterAgentProvider, type Trace } from "../../src/agent";
import { Classifier, OpenRouterProvider } from "../../src/decisions";
import { ActionService, PiholeAdapter, SqliteLedger, type Proposal } from "../../src/actions";
import { createLabVerifier } from "../../src/actions/lab-verifier";

test.skipIf(process.env.RG_AGENT_LIVE!=="1")("hosted Clef -> OpenAI approved tool -> real lab DNS deny -> undo",async()=>{
  const lab=process.env.RG_LAB_DIR;if(!lab||!process.env.OPENROUTER_API_KEY)throw new Error("Explicit lab and provider configuration required");
  const password=readFileSync(join(lab,".env"),"utf8").match(/^PIHOLE_API_PASSWORD=(.+)$/m)?.[1]?.replace(/^['"]|['"]$/g,"");
  if(!password)throw new Error("Lab credential unavailable");
  const group=Number(process.env.RG_LAB_GROUP);if(!Number.isSafeInteger(group)||group<1)throw new Error("Dedicated group required");
  const adapter=new PiholeAdapter({base_url:"http://127.0.0.1:8053/api",password:()=>password,domain:"flagged.lab.test",group_id:group});
  const dir=mkdtempSync(join(tmpdir(),"rg-agent-live-"));const ledger=new SqliteLedger(join(dir,"actions.sqlite"));
  const verify=createLabVerifier(lab);let digest:string|null=null;
  const now=Date.now();let revision="a".repeat(64);
  const p:Proposal={action:"dns-deny",network_scope:"lab:rg-lab",resolver_id:"pihole-lab",domain:"flagged.lab.test",group_id:group,
    evidence_revision:revision,created_at:now,expires_at:now+120_000};
  const service=new ActionService({ledger,adapter,verify,now:Date.now,evidence_revision:()=>revision,
    policy:{network_scope:p.network_scope,resolver_id:p.resolver_id,group_id:group,allowed_domains:[p.domain],max_duration_ms:120_000}});
  try {
    expect(await adapter.read(p.domain)).toBeNull();
    const before=await verify(p,"resolved");expect(before.target).toBe("resolved");expect(before.benign).toBe("resolved");
    revision=createHash("sha256").update(JSON.stringify(before)).digest("hex");p.evidence_revision=revision;
    const observation:Trace={id:"trace:baseline",at:before.checked_at,kind:"observation",mode:"vm-live",
      summary:"Owned isolated lab client resolved configured test indicator and benign domain. This is a controlled test, not live malware.",evidence_ids:["observation:"+revision]};
    const judgment=await new Classifier(new OpenRouterProvider("cloudflare/clef",()=>process.env.OPENROUTER_API_KEY!)).classify({
      evidence_revision:revision,evidence_ids:observation.evidence_ids,coverage:"fresh",mode:"vm-live",
      facts:{queries:1,lab_indicator_match:true,novel_domain:false,benign_probe_ok:true}});
    expect(judgment.inference_status).toBe("succeeded");expect(judgment.category).toBe("suspicious");
    digest=service.propose(p).digest;service.approve(digest,"operator-authorized-isolated-integration-test");
    const currentDigest=digest;
    const traces=():Trace[]=>[observation,...ledger.history(currentDigest).map(e=>({id:`trace:action-${e.seq}`,at:e.at??0,kind:e.status,
      mode:"vm-live" as const,summary:`Action ${e.status}. ${e.detail}. Independent verification: ${JSON.stringify(e.verification)}`,evidence_ids:observation.evidence_ids}))];
    const loop=new AgentLoop({revision:()=>revision,traces,
      finding:(kind,rev)=>kind==="dns-deny"&&rev===revision&&before.target==="resolved"&&before.benign==="resolved"?"finding:"+revision:null,
      propose:async kind=>{if(kind!=="dns-deny")throw new Error("Unsupported router adapter");return ledger.get(currentDigest);},
      execute:async id=>{if(id!==currentDigest)throw new Error("Unknown proposal");return service.execute(id);},
      status:async id=>ledger.get(id)},new OpenRouterAgentProvider(()=>process.env.OPENROUTER_API_KEY!));
    const report=await loop.run({evidence_revision:revision,proposal_digests:[currentDigest],judgment:judgment.category});
    const applied=ledger.get(currentDigest);
    expect(report.status).toBe("complete");expect(report.explanation?.citations.length).toBeGreaterThan(0);
    expect(report.calls.some(c=>c.name==="execute_approved"&&c.ok)).toBe(true);
    expect(applied.status).toBe("active");expect(applied.verification?.target).toBe("blocked");expect(applied.verification?.benign).toBe("resolved");
    const restored=await service.undo(currentDigest);expect(restored.status).toBe("reverted");
    expect(await adapter.read(p.domain)).toBeNull();
    console.log(JSON.stringify({scenario:"controlled lab DNS indicator",topology:"isolated containers in Docker Desktop VM",
      classification:{model:judgment.model,provider:judgment.provider,category:judgment.category,cost_usd:judgment.cost_usd},
      agent:{model:report.model,status:report.status,responses:report.responses,calls:report.calls,explanation:report.explanation},
      applied:applied.verification,restored:restored.verification}));
  } finally {
    if(digest)await service.undo(digest);
    const unfinished=ledger.list().some(x=>["executing","active","ambiguous","undoing","rollback-unverified"].includes(x.status));
    try {await adapter.close();} finally {ledger.close();if(!unfinished)rmSync(dir,{recursive:true});else console.error("Inspect retained action journal",dir);}
  }
},90_000);
