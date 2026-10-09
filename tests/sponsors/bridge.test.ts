// The UI-facing bridge takes core Observations and the real action journal,
// and must report truthfully which backend served each answer.
import { afterAll, afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { MongoClient } from "mongodb";

import { SqliteLedger } from "../../src/actions/ledger.js";
import { ActionService } from "../../src/actions/service.js";
import type { DnsAdapter, Rule, Verification } from "../../src/actions/types.js";
import { SponsorBridge, type MongoBoundaryOptions } from "../../src/adapters/sponsors/index.js";
import { checkClickHouseEndpoint, checkMongoEndpoint } from "../../src/adapters/sponsors/endpoints.js";
import { LocalActionProjection } from "../../src/adapters/sponsors/local/action-projection.js";
import { ResilientActionProjection, ResilientObservationStore } from "../../src/adapters/sponsors/resilient.js";
import { PINS } from "../../src/adapters/sponsors/tools/pins.js";
import { FLAGGED, dnsObservation, preActionObservations, uniqueScope } from "./fixtures/observations.js";

const ledgers: SqliteLedger[] = [];
afterEach(() => ledgers.splice(0).forEach((ledger) => ledger.close()));

/** Minimal resolver fake: the bridge must work with any DnsAdapter the action core is given. */
class FakeDns implements DnsAdapter {
  rule: Rule | null = null;
  async read() { return this.rule && { ...this.rule }; }
  async create(rule: Rule) { this.rule = { ...rule }; }
  async remove() { this.rule = null; }
}

function journal(scope: string) {
  let now = Date.parse("2026-10-09T21:00:00.000Z");
  const dns = new FakeDns();
  const ledger = new SqliteLedger(join(mkdtempSync(join(tmpdir(), "rg-bridge-")), "journal.sqlite"), () => now);
  ledgers.push(ledger);
  const verify = async (): Promise<Verification> => ({
    target: dns.rule ? "blocked" : "resolved",
    benign: "resolved",
    checked_at: (now += 1_000),
    mode: "synthetic",
  });
  const service = new ActionService({
    ledger,
    adapter: dns,
    policy: { network_scope: scope, resolver_id: "lab-resolver", group_id: 2, allowed_domains: [FLAGGED], max_duration_ms: 3_600_000 },
    verify,
    now: () => (now += 1_000),
    evidence_revision: () => "evidence:bridge",
  });
  const created_at = (now += 1_000);
  const proposal = {
    action: "dns-deny" as const,
    network_scope: scope,
    resolver_id: "lab-resolver",
    domain: FLAGGED,
    group_id: 2,
    evidence_revision: "evidence:bridge",
    created_at,
    expires_at: created_at + 600_000,
  };
  return { ledger, service, proposal };
}

const WINDOW = { from: "2026-10-09T19:00:00.000Z", to: "2026-10-09T21:00:00.000Z" };

describe("sponsor bridge without sponsors", () => {
  test("unconfigured sponsors are reported unavailable and the bridge still works locally", async () => {
    const bridge = await SponsorBridge.open({});
    const scope = uniqueScope("bridge-local");

    const recorded = await bridge.recordObservations([
      ...preActionObservations(scope),
      dnsObservation(scope, "svc-1", "2026-10-09T20:00:00.000Z", { available: false }, { kind: "service_status" }),
    ]);
    const evidence = await bridge.evidence({ domain: FLAGGED, network_scope: scope, ...WINDOW });
    const report = bridge.status();

    expect(recorded).toEqual({ accepted: 4, ignored: 1, backend: "local" });
    expect(evidence).toMatchObject({ backend: "local", evidence: { lookups: 3 } });
    expect(report.sponsors.map((status) => [status.sponsor, status.health, status.serving_backend])).toEqual([
      ["clickhouse", "unavailable", "local"],
      ["mongodb", "unavailable", "local"],
    ]);
    expect(report.sponsors.every((status) => status.detail.includes("not configured"))).toBe(true);
    expect(report.eligibility.mongodb).toBe("unconfirmed");
    await bridge.close();
  });

  test("unreachable sponsors do not throw; the reason is reported", async () => {
    const bridge = await SponsorBridge.open({
      clickhouse: { url: "http://127.0.0.1:9", timeoutMs: 500 },
      mongodb: { uri: "mongodb://127.0.0.1:9", serverSelectionTimeoutMs: 300 },
    });

    expect(bridge.status().sponsors.map((status) => status.health)).toEqual(["unavailable", "unavailable"]);
    expect(bridge.status().sponsors.every((status) => !status.detail.includes("not configured"))).toBe(true);
    await bridge.close();
  });

  test("mirrors the real action journal: nothing before, every durable event after", async () => {
    const bridge = await SponsorBridge.open({});
    const scope = uniqueScope("bridge-journal");
    const { ledger, service, proposal } = journal(scope);
    const { digest } = service.propose(proposal);
    expect((await bridge.actions(scope)).value).toEqual([]);

    service.approve(digest, "operator:bridge");
    await service.execute(digest);
    const mirrored = await bridge.mirrorJournal(ledger, digest);
    await service.undo(digest);
    const final = await bridge.mirrorJournal(ledger, digest);

    expect(mirrored).toMatchObject({ ok: true, backend: "local", error: null });
    expect(final.events.map((event): string => event.status)).toEqual(["proposed", "approved", "executing", "active", "undoing", "reverted"]);
    expect((await bridge.actions(scope)).value.map((entry) => [entry.digest, entry.status, entry.revision])).toEqual([[digest, "reverted", 6]]);
    expect((await bridge.actionHistory(digest)).value).toHaveLength(6);
    expect((await bridge.journalAudit(digest)).value.map((event): string => event.kind)).toEqual(final.events.map((event) => event.status));
    expect(bridge.status().last_mirror_error).toBeNull();
    await bridge.close();
  });

  test("a journal/projection mismatch is reported, not thrown or hidden", async () => {
    const projection = new LocalActionProjection();
    const bridge = new SponsorBridge(new ResilientObservationStore(null, null), new ResilientActionProjection(projection, "test"));
    const { ledger, service, proposal } = journal(uniqueScope("bridge-mismatch"));
    const { digest } = service.propose(proposal);
    await bridge.mirrorJournal(ledger, digest);
    await projection.publish({ ...ledger.get(digest), status: "revoked", detail: "forged" }, 1);
    service.approve(digest, "operator:bridge");

    const report = await bridge.mirrorJournal(ledger, digest);

    expect(report.ok).toBe(false);
    expect(report.error).toContain("refusing to continue");
    expect(bridge.status().last_mirror_error).toContain(digest);
  });

  test("a recorded security scan is shown with its revision and audited", async () => {
    const store = new ResilientObservationStore(null, null);
    const bridge = new SponsorBridge(store, new ResilientActionProjection(null, null));
    const scan = {
      tool: "semgrep" as const, status: "passed" as const, version: PINS.semgrep.version, revision: "f".repeat(40), worktree_dirty: false,
      rules_sha256: "0".repeat(64), targets: ["src"], scanned_files: 25, findings: [], errors: [], duration_ms: 1700,
      scanned_at: "2026-10-09T21:30:00.000Z",
    };
    await bridge.recordSecurityScan(scan);

    expect(bridge.status().security_scan).toEqual(scan);
    expect((await store.auditTrail("security_scan")).map((event) => [event.kind, JSON.parse(event.detail).revision])).toEqual([
      ["security_scan", "f".repeat(40)],
    ]);
  });
});

/** Records every connection attempt; any attempt against an invalid endpoint is a boundary failure. */
function recordingDeps() {
  const attempts: string[] = [];
  const fetchInits: (RequestInit | undefined)[] = [];
  const mongoOptions: MongoBoundaryOptions[] = [];
  return {
    attempts,
    fetchInits,
    mongoOptions,
    deps: {
      fetch: (async (input: string | URL | Request, init?: RequestInit) => {
        attempts.push(`fetch ${new URL(String(input)).host}`);
        fetchInits.push(init);
        throw new Error("network disabled in test");
      }) as unknown as typeof fetch,
      mongoClient: (uri: string, options: MongoBoundaryOptions) => {
        attempts.push(`mongo ${uri.length}`);
        mongoOptions.push(options);
        throw new Error("network disabled in test");
      },
    },
  };
}

describe("sponsor endpoint boundary", () => {
  const badClickHouse = [
    ["http://192.0.2.10:18123", "host must be"],
    ["http://localhost:18123", "host must be"],
    ["http://clickhouse.example:18123", "host must be"],
    ["http://user:secret@127.0.0.1:18123", "credentials not allowed"],
    ["http://127.0.0.1", "explicit port required"],
    ["https://127.0.0.1:18123", "scheme must be http:"],
    ["http://127.0.0.1:18123/?user=default&password=x", "query options"],
    ["http://127.0.0.1:18123/db", "path not allowed"],
    ["not a url", "not a URL"],
  ] as const;
  const badMongo = [
    ["mongodb://192.0.2.10:27717", "host must be"],
    ["mongodb://localhost:27717", "host must be"],
    ["mongodb+srv://cluster.example/", "scheme must be mongodb://"],
    ["mongodb://user:secret@127.0.0.1:27717", "credentials not allowed"],
    ["mongodb://127.0.0.1", "explicit port required"],
    ["mongodb://127.0.0.1:27717,127.0.0.1:27718", "exactly one host"],
    ["mongodb://127.0.0.1:27717/?tls=false", "query options"],
    ["mongodb://127.0.0.1:27717/otherdb", "database belongs in config.database"],
  ] as const;

  test.each(badClickHouse)("ClickHouse %s is refused before any request", async (url, reason) => {
    const { attempts, deps } = recordingDeps();
    const bridge = await SponsorBridge.open({ clickhouse: { url } }, deps);
    const [clickhouse] = bridge.status().sponsors;

    expect(attempts).toEqual([]);
    expect(clickhouse).toMatchObject({ health: "unavailable", serving_backend: "local" });
    expect(clickhouse!.detail).toContain(reason);
    expect(clickhouse!.detail).not.toContain("secret");
    await bridge.close();
  });

  test.each(badMongo)("MongoDB %s is refused before any client exists", async (uri, reason) => {
    const { attempts, deps } = recordingDeps();
    const bridge = await SponsorBridge.open({ mongodb: { uri } }, deps);
    const [, mongodb] = bridge.status().sponsors;

    expect(attempts).toEqual([]);
    expect(mongodb).toMatchObject({ health: "unavailable", serving_backend: "local" });
    expect(mongodb!.detail).toContain(reason);
    expect(mongodb!.detail).not.toContain("secret");
    await bridge.close();
  });

  test("valid loopback endpoints are attempted (and only those)", async () => {
    const { attempts, deps } = recordingDeps();
    const bridge = await SponsorBridge.open(
      { clickhouse: { url: "http://127.0.0.1:18123" }, mongodb: { uri: "mongodb://127.0.0.1:27717" } },
      deps,
    );

    expect(attempts).toEqual(["fetch 127.0.0.1:18123", `mongo ${"mongodb://127.0.0.1:27717".length}`]);
    expect(bridge.status().sponsors.map((status) => status.health)).toEqual(["unavailable", "unavailable"]);
    await bridge.close();
  });

  test("transport options keep validated endpoints from escaping loopback", async () => {
    const { fetchInits, mongoOptions, deps } = recordingDeps();
    const bridge = await SponsorBridge.open(
      { clickhouse: { url: "http://127.0.0.1:18123" }, mongodb: { uri: "mongodb://127.0.0.1:27717" } },
      deps,
    );

    // No redirect following for ClickHouse; no replica-set discovery for MongoDB.
    expect(fetchInits).toHaveLength(1);
    expect(fetchInits[0]?.redirect).toBe("error");
    expect(mongoOptions).toEqual([{ serverSelectionTimeoutMS: 1_500, directConnection: true }]);
    await bridge.close();
  });

  test("IPv6 loopback is accepted", () => {
    expect(checkClickHouseEndpoint("http://[::1]:18123")).toEqual({ ok: true, url: "http://[::1]:18123" });
    expect(checkMongoEndpoint("mongodb://[::1]:27717")).toEqual({ ok: true, url: "mongodb://[::1]:27717" });
  });
});

const live = process.env.RG_SPONSOR_LIVE === "1";
const config = {
  clickhouse: { url: process.env.RG_CLICKHOUSE_URL ?? "http://127.0.0.1:18123" },
  mongodb: { uri: process.env.RG_MONGO_URI ?? "mongodb://127.0.0.1:27717", database: `router_guard_bridge_test_${crypto.randomUUID().slice(0, 8)}` },
};
afterAll(async () => {
  if (live) {
    const client = new MongoClient(config.mongodb.uri);
    await client.db(config.mongodb.database).dropDatabase();
    await client.close();
  }
});

(live ? describe : describe.skip)("sponsor bridge with live sponsors", () => {
  test("ClickHouse and MongoDB serve at the pinned versions; a new bridge sees the durable projection", async () => {
    const scope = uniqueScope("bridge-live");
    const bridge = await SponsorBridge.open(config);
    const { ledger, service, proposal } = journal(scope);
    await bridge.recordObservations(preActionObservations(scope));
    const { digest } = service.propose(proposal);
    service.approve(digest, "operator:bridge");
    await service.execute(digest);
    await bridge.mirrorJournal(ledger, digest);

    expect(bridge.status().sponsors.map((status) => [status.health, status.serving_backend, status.version])).toEqual([
      ["ok", "clickhouse", PINS.clickhouse.version],
      ["ok", "mongodb", PINS.mongodb.version],
    ]);
    expect((await bridge.evidence({ domain: FLAGGED, network_scope: scope, ...WINDOW })).backend).toBe("clickhouse");
    await bridge.close();

    const reopened = await SponsorBridge.open(config);
    await service.undo(digest);
    const report = await reopened.mirrorJournal(ledger, digest);
    expect(report).toMatchObject({ ok: true, backend: "mongodb" });
    expect((await reopened.actionHistory(digest)).value.map((entry): string => entry.status)).toEqual([
      "proposed", "approved", "executing", "active", "undoing", "reverted",
    ]);
    expect((await reopened.journalAudit(digest)).backend).toBe("clickhouse");
    await reopened.close();
  });
});
