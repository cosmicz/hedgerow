// The proof's action path is the real action core over SyntheticLab. These
// tests pin that the lab behaves like a resolver: the deny rule changes what
// lookups return, and every lookup is a synthetic observation.
import { describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { SqliteLedger } from "../../src/actions/ledger.js";
import { ActionService } from "../../src/actions/service.js";
import { BENIGN, FLAGGED } from "../../src/adapters/sponsors/scenario.js";
import { SyntheticClock, SyntheticLab } from "../../src/adapters/sponsors/synthetic-lab.js";

function setup() {
  const clock = new SyntheticClock(Date.parse("2026-10-09T20:00:00.000Z"));
  const lab = new SyntheticLab({ network_scope: "lab-unit", clock, probe_client: "192.0.2.53", benign_domain: BENIGN });
  const ledger = new SqliteLedger(join(mkdtempSync(join(tmpdir(), "rg-synthetic-")), "journal.sqlite"));
  const service = new ActionService({
    ledger,
    adapter: lab.adapter,
    policy: { network_scope: "lab-unit", resolver_id: "synthetic-resolver", group_id: 2, allowed_domains: [FLAGGED], max_duration_ms: 3_600_000 },
    verify: lab.verify,
    now: () => clock.now(),
    evidence_revision: () => "evidence:unit",
  });
  const created_at = clock.now();
  const proposal = {
    action: "dns-deny" as const,
    network_scope: "lab-unit",
    resolver_id: "synthetic-resolver",
    domain: FLAGGED,
    group_id: 2,
    evidence_revision: "evidence:unit",
    created_at,
    expires_at: created_at + 600_000,
  };
  return { lab, ledger, service, proposal };
}

describe("synthetic lab under the action core", () => {
  test("approved deny changes lookups from answered to blocked, undo restores them", async () => {
    const { lab, ledger, service, proposal } = setup();
    expect(lab.lookup(FLAGGED, "192.0.2.10")).toBe("answered");

    const { digest } = service.propose(proposal);
    service.approve(digest, "operator:unit");
    const executed = await service.execute(digest);

    expect(executed.status).toBe("active");
    expect(executed.verification).toMatchObject({ target: "blocked", benign: "resolved", mode: "synthetic" });
    expect(lab.lookup(FLAGGED, "192.0.2.10")).toBe("blocked");
    expect(lab.lookup(BENIGN, "192.0.2.10")).toBe("answered");

    expect((await service.execute(digest)).status).toBe("active");
    expect(lab.creates).toBe(1);

    expect((await service.undo(digest)).status).toBe("reverted");
    expect(lab.hasRule(FLAGGED)).toBe(false);
    expect(lab.lookup(FLAGGED, "192.0.2.10")).toBe("answered");
    expect(lab.ruleWindows).toHaveLength(1);
    expect(lab.ruleWindows[0]!.removed_at).toBeGreaterThan(lab.ruleWindows[0]!.created_at);
    ledger.close();
  });

  test("unapproved proposal leaves the resolver unchanged", async () => {
    const { lab, ledger, service, proposal } = setup();
    const { digest } = service.propose(proposal);

    await expect(service.execute(digest)).rejects.toThrow();
    expect(lab.creates).toBe(0);
    expect(lab.lookup(FLAGGED, "192.0.2.10")).toBe("answered");
    ledger.close();
  });

  test("every lookup is drained once as a synthetic dns_query observation", () => {
    const { lab, ledger } = setup();
    lab.lookup(FLAGGED, "192.0.2.10");
    lab.lookup(BENIGN, "192.0.2.11");

    const drained = lab.drain();
    expect(drained.map((observation) => [observation.kind, observation.mode, observation.payload])).toEqual([
      ["dns_query", "synthetic", { domain: FLAGGED, client: "192.0.2.10", status: "answered" }],
      ["dns_query", "synthetic", { domain: BENIGN, client: "192.0.2.11", status: "answered" }],
    ]);
    expect(lab.drain()).toEqual([]);
    ledger.close();
  });
});
