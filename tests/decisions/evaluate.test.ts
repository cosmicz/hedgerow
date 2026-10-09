import { expect, test } from "bun:test";
import { baseline, Classifier } from "../../src/decisions";
import { evaluate, heldOut } from "../../src/decisions/evaluate";
test("evaluator measures incorrect judgments and abstention separately, never inflates missing-provider accuracy",async()=>{
  const correct = await evaluate(async i=>baseline(i));
  const broken = await evaluate(async i=>({...baseline(i),category:"benign"}));
  expect(correct.metrics.correct).toBe(heldOut.length);
  expect(correct.metrics.abstentions).toBe(4);
  expect(broken.metrics.correct).toBe(2);
  expect(broken.metrics.false_negatives).toBe(2);
  expect(broken.metrics).not.toEqual(correct.metrics);
  expect(correct.metrics.provider_calls).toBe(0);
  expect(correct.metrics.reported_cost_usd).toBe(0);
});
test("failed inference never earns agreement or counts as model abstention",async()=>{
  const unavailable=new Classifier({name:"unavailable",model:"fixture",provenance:"fake",decide:async()=>{throw new Error("offline");}});
  const result=await evaluate(i=>unavailable.classify(i));
  expect(result.metrics.provider_calls).toBe(6);
  expect(result.metrics.inference_failed).toBe(6);
  expect(result.metrics.inference_succeeded).toBe(0);
  expect(result.metrics.correct).toBe(2); // Only the two local no-call guards.
  expect(result.metrics.abstentions).toBe(2);
  expect(result.metrics.hosted_agreement).toEqual({correct:0,cases:0,rate:null});
});
test("hosted denominator includes only successful hosted judgments",async()=>{
  const result=await evaluate(async i=>({...baseline(i),provenance:"hosted",inference_status:i.facts.queries===40?"failed":"succeeded"}));
  expect(result.metrics.inference_succeeded).toBe(7);expect(result.metrics.inference_failed).toBe(1);
  expect(result.metrics.hosted_agreement).toEqual({correct:7,cases:7,rate:1});
  expect(result.metrics.correct).toBe(7);
});
