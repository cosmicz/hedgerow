// Live, redacted Senso proof: `RG_SENSO_ENV_FILE=<rig .env> bun run senso:proof`
// (reads only SENSO_API_KEY from that file) or with SENSO_API_KEY already set.
// Ingests the public guidance document (once) and retrieves both fixed topics
// with citations. The artifact holds only public guidance text, Senso ids and
// timings; the API key is never written. Exits non-zero unless both topics
// return passages cited to the guidance document.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { GUIDANCE_QUERIES, SensoGuidance, readSensoKey, type GuidanceTopic } from "./index.js";

const envFile = process.env.RG_SENSO_ENV_FILE;
const senso = envFile ? SensoGuidance.fromEnvFile(envFile) : SensoGuidance.fromEnv(process.env);
const results = [];
for (const topic of Object.keys(GUIDANCE_QUERIES) as GuidanceTopic[]) {
  results.push(await senso.guidance(topic));
}
const status = senso.status();
const checks = results.map((result) => ({
  topic: result.topic,
  ok: result.status === "ok" && result.passages.length > 0 &&
    result.citations.length === 1 && result.citations[0] === result.document.content_id,
}));
const passed = status.health === "ok" && checks.every((entry) => entry.ok);
const artifact = { generated_at: new Date().toISOString(), mode: "live-sponsor-public-document", passed, status, checks, results };

const text = `${JSON.stringify(artifact, null, 2)}\n`;
const key = envFile ? readSensoKey(envFile) : process.env.SENSO_API_KEY;
if (key && text.includes(key)) {
  throw new Error("refusing to write an artifact containing the API key");
}
const outDir = join(import.meta.dir, "../../../../proof/senso");
mkdirSync(outDir, { recursive: true });
const file = join(outDir, `${artifact.generated_at.replace(/[:.]/g, "-")}.json`);
writeFileSync(file, text);
for (const result of results) {
  console.log(result.status === "ok"
    ? `${result.topic}: ok, ${result.passages.length} passages, citations ${result.citations.join(",")}, ${result.latency_ms} ms`
    : `${result.topic}: ${result.status} (${result.reason})`);
}
console.log(`senso: ${status.health} — ${status.detail}`);
console.log(`Overall: ${passed ? "PASS" : "FAIL"}; wrote proof/senso/${file.split("/").at(-1)}`);
process.exitCode = passed ? 0 : 1;
