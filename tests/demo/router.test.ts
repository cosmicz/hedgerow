import { expect, test } from "bun:test";
import { DemoRouter } from "../../src/demo/router";
import type { RouterLabController } from "../../src/router/controller";

test("router UI requires measured evidence and exact human approval before one bounded agent mutation", async () => {
  const now = Date.now(), revision = "b".repeat(64), digest = "a".repeat(64);
  let clock = now, approved = false, rotations = 0;
  const backend: RouterLabController = {
    prepare: async () => ({phase:"prepared", evidence_revision:revision, topology:"internal-docker-only", runtime:"openwrt-userland-container"}),
    attack: async () => ({phase:"attacked", evidence_revision:revision, attempts:[
      {role:"unrelated",outcome:"rejected",started_at:new Date(now-3).toISOString(),finished_at:new Date(now-2).toISOString()},
      {role:"seeded-before",outcome:"accepted",started_at:new Date(now-1).toISOString(),finished_at:new Date(now).toISOString()},
    ]}),
    propose: async () => ({phase:"proposed",digest,evidence_revision:revision,expires_at:new Date(now+300000).toISOString(),confirmation:"Change only the owned lab password"}),
    approveFromUi: async id => {expect(id).toBe(digest);approved=true;return {phase:"approved"};},
    rotate: async () => {expect(approved).toBe(true);rotations++;return {phase:"rotated",trace:{target_id:"cyber26-openwrt-lab",evidence_revision:"sha256:"+revision,classification:"lab-only-credential-abuse",attempts:[
      {attempt:"unrelated-credential",outcome:"rejected",occurred_at:new Date(now-3).toISOString()},
      {attempt:"old-credential-before-rotation",outcome:"accepted",occurred_at:new Date(now-2).toISOString()},
      {attempt:"old-credential-after-rotation",outcome:"rejected",occurred_at:new Date(now-1).toISOString()},
      {attempt:"replacement-credential-after-rotation",outcome:"accepted",occurred_at:new Date(now).toISOString()},
    ]}};},
    cleanup: async () => ({phase:"down"}),
  };
  const outputs = [{output:[{type:"function_call",name:"execute_approved",call_id:"one",arguments:JSON.stringify({digest})}]},
    {output:[{type:"message",content:[{type:"output_text",text:JSON.stringify({text:"The lab login checks verified the change.",citations:[`trace:router-measured-3-${revision.slice(0,16)}`]})}]}]}];
  const router = new DemoRouter({backend,now:()=>clock,classify:async()=>[],agent:{model:"fixture",provenance:"fake",respond:async()=>outputs.shift()}});
  await expect(router.command("router-propose")).rejects.toThrow();
  await router.command("router-prepare");await router.command("router-attack");await router.command("router-propose");
  await expect(router.command("router-execute",digest)).rejects.toThrow();
  await expect(router.command("router-approve","c".repeat(64))).rejects.toThrow();
  expect(rotations).toBe(0);
  await router.command("router-approve",digest);await router.command("router-execute",digest);
  expect(rotations).toBe(1);expect(router.snapshot().phase).toBe("rotated");
  expect(router.snapshot().agent?.explanation?.citations).toHaveLength(1);
  await expect(router.command("router-execute",digest)).rejects.toThrow();expect(rotations).toBe(1);
  clock += 300001;
  await expect(router.command("router-approve",digest)).rejects.toThrow();
  await router.command("router-cleanup");expect(router.snapshot().phase).toBe("down");
  expect(router.snapshot().trace?.attempts).toHaveLength(4);
});
