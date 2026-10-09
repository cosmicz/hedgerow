import { expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRouterLabController, type RedactedAuthAttempt } from "../../src/router/controller";
import { RouterApprovalJournal } from "../../src/router/approval";

function fixture() {
  let tick=Date.now(), revision="sha256:"+"a".repeat(64), rotations=0, fail=false;
  const clock={now:()=>new Date(++tick).toISOString()};
  const attempt=(role:RedactedAuthAttempt["role"],outcome:RedactedAuthAttempt["outcome"]):RedactedAuthAttempt=>
    ({role,outcome,started_at:clock.now(),finished_at:clock.now()});
  const path=mkdtempSync(join(tmpdir(),"router-controller-"));
  const controller=createRouterLabController({privateDirectory:path,now:clock,runner:{run:async()=>{throw Error("unexpected spawn");}},
    transport:{
      prepare:async()=>{},cleanup:async()=>{},measuredRevision:async()=>revision,
      attack:async()=>[attempt("unrelated","rejected"),attempt("seeded-before","accepted")],
      rotateAndVerify:async()=>{rotations++;if(fail)throw Error("uncertain");return [attempt("seeded-after","rejected"),attempt("replacement","accepted")];},
    }});
  return {controller,clock,path,rotations:()=>rotations,change:()=>{revision="sha256:"+"b".repeat(64);},fail:()=>{fail=true;}};
}
test("controller binds actual attack and remeasures before a one-shot approved rotation",async()=>{
  const s=fixture();await s.controller.prepare();const attack=await s.controller.attack();
  expect(attack.evidence_revision).not.toBe("sha256:"+"a".repeat(64));
  const p=await s.controller.propose();expect(p.evidence_revision).toBe(attack.evidence_revision);
  await expect(s.controller.rotate(p.digest)).rejects.toThrow();expect(s.rotations()).toBe(0);
  await s.controller.approveFromUi(p.digest,"oc",true);
  s.change();await expect(s.controller.rotate(p.digest)).rejects.toThrow();expect(s.rotations()).toBe(0);
});
test("measured success is journalled; uncertain write is ambiguous and never replayed",async()=>{
  for(const fails of [false,true]) {
    const s=fixture();await s.controller.prepare();await s.controller.attack();const p=await s.controller.propose();
    await s.controller.approveFromUi(p.digest,"oc",true);
    if(fails){s.fail();await expect(s.controller.rotate(p.digest)).rejects.toThrow();}
    else expect((await s.controller.rotate(p.digest)).trace.attempts.at(-1)?.outcome).toBe("accepted");
    expect(s.rotations()).toBe(1);
    await expect(s.controller.rotate(p.digest)).rejects.toThrow();expect(s.rotations()).toBe(1);
    const journal=new RouterApprovalJournal(join(s.path,"approvals.sqlite"),s.clock);
    expect(journal.status(p.digest)).toBe(fails?"ambiguous":"applied");journal.close();
  }
});
