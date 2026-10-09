// Live-local sponsor backends. Run with RG_SPONSOR_LIVE=1 after
// `bun run sponsors:services start`; both services bind 127.0.0.1 only.
// Without the flag these suites are reported as skipped, never as passed.
import { afterAll, describe, expect, test } from "bun:test";
import { MongoClient } from "mongodb";

import { ClickHouseHttp } from "../../src/adapters/sponsors/clickhouse/http.js";
import { ClickHouseObservationStore } from "../../src/adapters/sponsors/clickhouse/observation-store.js";
import { LocalObservationStore } from "../../src/adapters/sponsors/local/observation-store.js";
import { MongoActionProjection } from "../../src/adapters/sponsors/mongodb/action-projection.js";
import { actionProjectionContract } from "./action-projection.contract.js";
import { observationStoreContract } from "./observation-store.contract.js";
import { FLAGGED, postActionObservations, preActionObservations, uniqueScope } from "./fixtures/observations.js";

const live = process.env.RG_SPONSOR_LIVE === "1";
const clickhouseUrl = process.env.RG_CLICKHOUSE_URL ?? "http://127.0.0.1:18123";
const mongoUri = process.env.RG_MONGO_URI ?? "mongodb://127.0.0.1:27717";

const http = new ClickHouseHttp({ url: clickhouseUrl, timeoutMs: 5_000 });
const mongo = new MongoClient(mongoUri, { serverSelectionTimeoutMS: 2_000 });
const projectionDb = `router_guard_test_${crypto.randomUUID().slice(0, 8)}`;

afterAll(async () => {
  if (live) {
    await mongo.db(projectionDb).dropDatabase();
  }
  await mongo.close();
});

observationStoreContract("clickhouse", () => new ClickHouseObservationStore(http), live);
actionProjectionContract("mongodb", () => new MongoActionProjection(mongo.db(projectionDb)), live);

(live ? describe : describe.skip)("clickhouse / local parity", () => {
  test("same synthetic fixture produces identical evidence from both backends", async () => {
    const scope = uniqueScope("parity");
    const observations = [...preActionObservations(scope), ...postActionObservations(scope)];
    const remote = new ClickHouseObservationStore(http);
    const local = new LocalObservationStore();
    await remote.record(observations);
    await local.record(observations);
    const query = { domain: FLAGGED, network_scope: scope, from: "2026-10-09T00:00:00.000Z", to: "2026-10-10T00:00:00.000Z" };

    expect(await remote.domainEvidence(query)).toEqual(await local.domainEvidence(query));
  });

  test("server reports a version", async () => {
    expect(await http.version()).toMatch(/^\d+\.\d+/);
  });
});
