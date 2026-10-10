import { expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ActionService, PiholeAdapter, SqliteLedger } from "../../src/actions";
import { createLabVerifier } from "../../src/actions/lab-verifier";

// Opt-in uses only arc-iz5s's owned, verified isolated container lab.
test.skipIf(process.env.RG_LIVE_TEST !== "1")("live lab: approve -> deny -> independent DNS verification -> undo", async () => {
  const lab = process.env.RG_LAB_DIR;
  if (!lab) throw new Error("Set RG_LAB_DIR to the verified isolated lab");
  const group = Number(process.env.RG_LAB_GROUP);
  if (!Number.isSafeInteger(group) || group < 1) throw new Error("Dedicated lab group required");
  const env = readFileSync(join(lab, ".env"), "utf8");
  const password = env.match(/^PIHOLE_API_PASSWORD=(.+)$/m)?.[1]?.replace(/^['"]|['"]$/g, "");
  if (!password) throw new Error("Lab credential is not configured");
  const adapter = new PiholeAdapter({ base_url: "http://127.0.0.1:8053/api", password: () => password,
    domain: "update-check.cloudsyncapi.net", group_id: group });
  const dir = mkdtempSync(join(tmpdir(), "rg-live-action-"));
  const ledger = new SqliteLedger(join(dir, "actions.sqlite"));
  const service = new ActionService({ ledger, adapter, verify: createLabVerifier(lab), now: Date.now,
    evidence_revision: () => "integration-owned-synthetic-domain-v1",
    policy: {network_scope: "lab:rg-lab", resolver_id: "pihole-lab", group_id: group,
      allowed_domains: ["update-check.cloudsyncapi.net"], max_duration_ms: 120_000} });
  let digest: string | null = null;
  try {
    expect(await adapter.read("update-check.cloudsyncapi.net")).toBeNull();
    const now = Date.now();
    const record = service.propose({action: "dns-deny", network_scope: "lab:rg-lab", resolver_id: "pihole-lab",
      group_id: group, domain: "update-check.cloudsyncapi.net", evidence_revision: "integration-owned-synthetic-domain-v1",
      created_at: now, expires_at: now + 60_000 });
    digest = record.digest;
    service.approve(digest, "operator-authorized-lab-test");
    const applied = await service.execute(digest);
    expect(applied.status).toBe("active");
    expect(applied.verification?.target).toBe("blocked");
    expect(applied.verification?.benign).toBe("resolved");
    const reverted = await service.undo(digest);
    expect(reverted.status).toBe("reverted");
    expect(await adapter.read("update-check.cloudsyncapi.net")).toBeNull();
    console.log(JSON.stringify({ mode: "vm-live", topology: "isolated containers inside Docker Desktop VM",
      action: "dns-deny", applied: applied.status, verification: applied.verification,
      undo: reverted.status, restored: reverted.verification }));
  } finally {
    if (digest) await service.undo(digest);
    const unfinished = ledger.list().some(x => !["reverted", "proposed", "approved", "failed", "conflict"].includes(x.status));
    await adapter.close(); ledger.close();
    if (!unfinished) rmSync(dir, { recursive: true });
    // Keep the exact journal for investigation if any mutation outcome is unknown.
    else console.error("Lab action needs inspection; retained local journal at", dir);
  }
}, 60_000);
