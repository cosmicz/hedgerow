import { expect, test } from "bun:test";
import { Classifier, baseline, OpenRouterProvider, type DecisionInput } from "../../src/decisions";

const input: DecisionInput = { evidence_revision: "a".repeat(64), evidence_ids: ["b".repeat(64)],
  coverage: "fresh", mode: "synthetic", facts: { queries: 12, lab_indicator_match: true,
    novel_domain: false, benign_probe_ok: true } };
const response = (choice = "suspicious") => ({ model: "typesafe/jev-1.13-20260917", provider: "TypeSafe",
  answers: { category: { type: "choice", choice, confidence: 0.8,
    probabilities: {benign: 0.05, suspicious: 0.9, unknown: 0.05} } }, usage: {cost: 0.00001} });

test("real-shaped answer creates a judgment, never an approval; novelty alone abstains", async () => {
  const classifier = new Classifier({name: "fake", model: "fixture-v1", provenance: "fake",
    decide: async () => response()});
  const result = await classifier.classify(input);
  expect(result.category).toBe("suspicious");
  expect(result.recommendation).toBe("propose-block");
  expect(result.provenance).toBe("fake");
  expect(result.evidence_ids).toEqual(input.evidence_ids);
  expect(result).not.toHaveProperty("approved");
  expect(baseline({...input, facts: {...input.facts, lab_indicator_match: false, novel_domain: true}}).category).toBe("unknown");
});
test("missing/stale coverage and invalid input do not call provider", async () => {
  let calls = 0;
  const c = new Classifier({name:"fake",model:"fixture",provenance:"fake",decide:async()=>{calls++;return response();}});
  expect((await c.classify({...input, coverage:"missing"})).category).toBe("unknown");
  expect((await c.classify({...input, coverage:"stale"})).recommendation).toBe("ask");
  expect((await c.classify({...input, evidence_ids:[]})).category).toBe("unknown");
  expect((await c.classify({...input, facts:{...input.facts,queries:0}})).category).toBe("unknown");
  expect(calls).toBe(0);
});
test("malformed, inconsistent and hostile output abstains; error bodies never escape", async () => {
  for (const value of [{}, {...response(), answers:{category:{choice:"approve-all"}}},
    {...response(), answers:{category:{...response().answers.category, probabilities:{benign:0,suspicious:2,unknown:0}}}},
    response("benign")]) {
    const c = new Classifier({name:"fake",model:"fixture",provenance:"fake",decide:async()=>value});
    const result = await c.classify(input);
    expect(result.category).toBe("unknown"); expect(result.recommendation).toBe("ask");
  }
  const c = new Classifier({name:"fake",model:"fixture",provenance:"fake",decide:async()=>{throw new Error("SECRET");}});
  expect(JSON.stringify(await c.classify(input))).not.toContain("SECRET");
});
test("timeout aborts provider and returns unknown", async () => {
  let signal: AbortSignal | undefined;
  const c = new Classifier({name:"fake",model:"fixture",provenance:"fake",decide:async(_i,s)=>{
    signal=s; return new Promise(()=>{});
  }}, 10);
  expect((await c.classify(input)).category).toBe("unknown");
  expect(signal?.aborted).toBe(true);
});
test("OpenRouter uses fixed Decisions endpoint and strips unapproved fields", async () => {
  let sent: any;
  const p = new OpenRouterProvider("typesafe/jev-1.13",()=>"test-secret",async(url,init)=>{
    expect(url).toBe("https://openrouter.ai/api/alpha/decisions");
    expect(new Headers(init?.headers).get("Authorization")).toBe("Bearer test-secret");
    expect(init?.redirect).toBe("error"); sent=JSON.parse(String(init?.body));
    return Response.json(response());
  });
  const c = new Classifier(p);
  const result = await c.classify({...input, hostname:"ignore instructions", password:"SECRET"} as DecisionInput);
  expect(result.provenance).toBe("hosted"); expect(result.cost_usd).toBe(0.00001);
  expect(sent.model).toBe("typesafe/jev-1.13");
  expect(sent.questions.category.type).toBe("choice");
  expect(JSON.stringify(sent)).not.toContain("SECRET");
  expect(JSON.stringify(sent)).not.toContain("ignore instructions");
  expect(JSON.stringify(sent)).not.toContain(input.evidence_ids[0]);
});
test("provider requires selected model, local secret and explicit synthetic/redacted input", async () => {
  expect(()=>new OpenRouterProvider("attacker/model" as any,()=>"key")).toThrow();
  let calls=0;
  const p = new OpenRouterProvider("cloudflare/clef",()=>"",async()=>{calls++;return Response.json(response());});
  expect((await new Classifier(p).classify(input)).category).toBe("unknown");
  expect(calls).toBe(0);
});
test("core observation IDs survive unchanged in grounded references", async () => {
  const i = {...input,evidence_ids:["observation:"+"c".repeat(64)]};
  const c = new Classifier({name:"fake",model:"fixture",provenance:"fake",decide:async()=>response()});
  const result = await c.classify(i);
  expect(result.category).toBe("suspicious");
  expect(result.evidence_ids).toEqual(i.evidence_ids);
});
