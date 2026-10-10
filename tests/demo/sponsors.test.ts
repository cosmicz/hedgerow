import { expect, test } from "bun:test";
import { SqliteLedger, ActionService } from "../../src/actions";
import { SponsorBridge } from "../../src/adapters/sponsors";
import { DemoSponsors } from "../../src/demo/sponsors";

test("late sponsor read cannot overwrite a timed-out snapshot or restart refresh", async () => {
  const ledger = new SqliteLedger(":memory:");
  const bridge = await SponsorBridge.open({});
  let release!: () => void;
  let reads = 0;
  bridge.actions = async () => { reads++; await new Promise<void>(r => { release = r; }); return { value: [], backend: "late-test-backend" }; };
  const sponsors = new DemoSponsors(bridge, 10);
  try {
    sponsors.schedule(ledger, null);
    await sponsors.settled();
    expect(sponsors.snapshot().error).toContain("timed out");
    expect(sponsors.snapshot().actions).toBeNull();
    release(); await Bun.sleep(1);
    expect(sponsors.snapshot().actions).toBeNull();
    expect(sponsors.snapshot().checked_at).toBeNull();
    expect(sponsors.snapshot().error).toContain("timed out");
    sponsors.schedule(ledger, null); await sponsors.settled();
    expect(reads).toBe(1);
  } finally { ledger.close(); await bridge.close(); }
});

test("unchanged histories are not mirrored again; a new approval is mirrored", async () => {
  const ledger = new SqliteLedger(":memory:");
  const bridge = await SponsorBridge.open({});
  const realMirror = bridge.mirrorJournal.bind(bridge);
  let writes = 0;
  bridge.mirrorJournal = async (...args) => { writes++; return realMirror(...args); };
  const sponsors = new DemoSponsors(bridge);
  const now = Date.now();
  const service = new ActionService({ ledger, now: () => now, evidence_revision: () => "rev",
    policy: { network_scope: "lab:rg-lab", resolver_id: "pihole-lab", group_id: 1, allowed_domains: ["update-check.cloudsyncapi.net"], max_duration_ms: 120000 },
    adapter: { read: async () => null, create: async () => {}, remove: async () => {} },
    verify: async () => ({ target: "resolved", benign: "resolved", checked_at: now, mode: "synthetic" }),
  });
  try {
    const record = service.propose({ action: "dns-deny", network_scope: "lab:rg-lab", resolver_id: "pihole-lab", group_id: 1,
      domain: "update-check.cloudsyncapi.net", evidence_revision: "rev", created_at: now, expires_at: now + 120000 });
    await sponsors.refresh(ledger, null); expect(writes).toBe(1);
    await sponsors.refresh(ledger, null); expect(writes).toBe(1);
    service.approve(record.digest, "test");
    await sponsors.refresh(ledger, null); expect(writes).toBe(2);
    expect(sponsors.snapshot().actions?.value[0]?.status).toBe("approved");
  } finally { ledger.close(); await bridge.close(); }
});
