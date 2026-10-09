// The proof must not leak a MongoDB client when its first command fails, and
// must apply the same endpoint boundary and transport options as the bridge.
import { describe, expect, test } from "bun:test";
import type { MongoClient } from "mongodb";

import { connectMongo } from "../../src/adapters/sponsors/proof-connect.js";

function fakeClient(buildInfo: () => Promise<unknown>) {
  const calls = { closed: 0, options: [] as unknown[] };
  const factory = (_uri: string, options: unknown) => {
    calls.options.push(options);
    return {
      db: () => ({ command: buildInfo, collection: () => ({}) }),
      close: async () => {
        calls.closed += 1;
      },
    } as unknown as MongoClient;
  };
  return { calls, factory };
}

describe("proof MongoDB connection", () => {
  test("a client whose buildInfo fails is closed and not returned", async () => {
    const { calls, factory } = fakeClient(async () => {
      throw new Error("server selection timed out");
    });

    const result = await connectMongo("mongodb://127.0.0.1:27717", "action_revisions_test", factory);

    expect(calls.closed).toBe(1);
    expect(result.client).toBeNull();
    expect(result.projection.status()).toMatchObject({ health: "unavailable", serving_backend: "local" });
    expect(result.projection.status().detail).toContain("server selection timed out");
  });

  test("a working client is returned open, with the boundary transport options", async () => {
    const { calls, factory } = fakeClient(async () => ({ version: "8.0.4" }));

    const result = await connectMongo("mongodb://127.0.0.1:27717", "action_revisions_test", factory);

    expect(calls.closed).toBe(0);
    expect(result.client).not.toBeNull();
    expect(calls.options).toEqual([{ serverSelectionTimeoutMS: 1_500, directConnection: true }]);
    expect(result.projection.status()).toMatchObject({ health: "ok", version: "8.0.4" });
  });

  test("an invalid endpoint creates no client", async () => {
    const { calls, factory } = fakeClient(async () => ({ version: "8.0.4" }));

    const result = await connectMongo("mongodb://192.0.2.10:27717", "action_revisions_test", factory);

    expect(calls.options).toEqual([]);
    expect(result.client).toBeNull();
    expect(result.projection.status().detail).toContain("invalid endpoint");
  });
});
