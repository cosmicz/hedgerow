import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Deliberately break one guard at a time in a disposable copy, never the worktree.
const mutations = [
  ["digest allowlist", "&&allowed.has(args.digest)", ""],
  ["deterministic finding", 'if(typeof finding!=="string"||!/^finding:[a-f0-9]{64}$/.test(finding))throw new Error();', ""],
  ["proposal revision", "&&args.evidence_revision===context.evidence_revision", ""],
  ["call ID dedupe", "||seen.has(call.call_id)", ""],
  ["strict execution args", '&&strictObject(args,["digest"])', ""],
] as const;
const source=readFileSync(new URL("../../src/agent/index.ts",import.meta.url),"utf8");
const test=readFileSync(new URL("./loop.test.ts",import.meta.url),"utf8");
for(const [name,needle,replacement] of mutations) {
  if(source.split(needle).length!==2)throw new Error(`Mutation must match exactly once: ${name}`);
  const directory=mkdtempSync(join(tmpdir(),"rg-guard-check-"));
  try {
    mkdirSync(join(directory,"src/agent"),{recursive:true});mkdirSync(join(directory,"tests/agent"),{recursive:true});
    writeFileSync(join(directory,"src/agent/index.ts"),source.replace(needle,replacement));
    writeFileSync(join(directory,"tests/agent/loop.test.ts"),test);
    const result=Bun.spawnSync(["bun","test","tests/agent/loop.test.ts"],{cwd:directory});
    if(result.exitCode===0)throw new Error(`Surviving mutation: ${name}`);
    if(!result.stderr.toString().includes("(fail)"))throw new Error(`Not a test assertion failure: ${name}`);
    console.log(`Caught: ${name}`);
  } finally {rmSync(directory,{recursive:true});}
}
