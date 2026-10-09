// Sponsor connections for the proof runner, with the same endpoint boundary
// and transport options as the runtime bridge. A client whose first command
// fails is closed here; only a working client is handed to the caller, which
// must close it.
import { MongoClient } from "mongodb";

import type { MongoBoundaryOptions } from "./bridge.js";
import { ClickHouseHttp } from "./clickhouse/http.js";
import { ClickHouseObservationStore } from "./clickhouse/observation-store.js";
import { checkClickHouseEndpoint, checkMongoEndpoint } from "./endpoints.js";
import { MongoActionProjection } from "./mongodb/action-projection.js";
import { ResilientActionProjection, ResilientObservationStore } from "./resilient.js";

export type MongoClientFactory = (uri: string, options: MongoBoundaryOptions) => MongoClient;

const defaultFactory: MongoClientFactory = (uri, options) => new MongoClient(uri, options);

export async function connectClickHouse(url: string): Promise<ResilientObservationStore> {
  const endpoint = checkClickHouseEndpoint(url);
  if (!endpoint.ok) {
    return new ResilientObservationStore(null, null, endpoint.reason);
  }
  const http = new ClickHouseHttp({ url: endpoint.url, timeoutMs: 2_000 });
  const version = await http.version().catch(() => null);
  return new ResilientObservationStore(new ClickHouseObservationStore(http), version);
}

export async function connectMongo(
  uri: string,
  collection: string,
  makeClient: MongoClientFactory = defaultFactory,
): Promise<{ projection: ResilientActionProjection; client: MongoClient | null }> {
  const endpoint = checkMongoEndpoint(uri);
  if (!endpoint.ok) {
    return { projection: new ResilientActionProjection(null, null, endpoint.reason), client: null };
  }
  let client: MongoClient | null = null;
  try {
    client = makeClient(endpoint.url, { serverSelectionTimeoutMS: 1_500, directConnection: true });
    const info = await client.db("admin").command({ buildInfo: 1 });
    const projection = new MongoActionProjection(client.db("router_guard_proof"), collection);
    return { projection: new ResilientActionProjection(projection, String(info.version)), client };
  } catch (error) {
    await client?.close().catch(() => {});
    return { projection: new ResilientActionProjection(null, null, (error as Error).message.slice(0, 200)), client: null };
  }
}
