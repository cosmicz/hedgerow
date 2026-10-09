// fetch.sh (downloads) and pins.ts (proof checks) must name the same artifacts.
import { describe, expect, test } from "bun:test";
import { join } from "node:path";

import { SEMGREP_VERSION } from "../../src/adapters/sponsors/semgrep/scan.js";
import { PINS, verifyBinaries } from "../../src/adapters/sponsors/tools/pins.js";

describe("sponsor runtime pins", () => {
  test("fetch.sh pins the same versions and digests as the proof", async () => {
    const fetch = await Bun.file(join(import.meta.dir, "../../src/adapters/sponsors/tools/fetch.sh")).text();

    expect(fetch).toContain(`CH_VERSION=${PINS.clickhouse.version}`);
    expect(fetch).toContain(`CH_SHA256=${PINS.clickhouse.sha256}`);
    expect(fetch).toContain(`MONGO_VERSION=${PINS.mongodb.version}`);
    expect(fetch).toContain(`MONGO_SHA256=${PINS.mongodb.archive_sha256}`);
    expect(fetch).toContain(`SEMGREP_VERSION=${PINS.semgrep.version}`);
    expect(SEMGREP_VERSION).toBe(PINS.semgrep.version);
  });

  test("missing tools directory never verifies", async () => {
    expect((await verifyBinaries(undefined)).every((entry) => !entry.matches && entry.actual_sha256 === null)).toBe(true);
  });
});
