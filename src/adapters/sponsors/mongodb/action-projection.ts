// MongoDB read-side projection of the action journal (cyber26-dni). Every
// accepted ActionRecord revision is one document; a unique (digest, revision)
// index is the compare-and-set, so two publishers of the same revision cannot
// both succeed. It stores and serves records only: approval and execution
// authority stay in the local journal. Untrusted strings are only ever values
// in fixed-shape filters, never keys or operators.
import type { Collection, Db } from "mongodb";

import { project } from "../local/action-projection.js";
import type { ActionProjection, ActionRecord, ProjectedAction, PublishResult } from "../types.js";

const DUPLICATE_KEY = 11000;

export class MongoActionProjection implements ActionProjection {
  readonly backend = "mongodb" as const;
  readonly durable = true;
  readonly #revisions: Collection<ProjectedAction>;
  #indexes: Promise<unknown> | null = null;

  constructor(db: Db, collectionName = "action_revisions") {
    this.#revisions = db.collection<ProjectedAction>(collectionName);
  }

  async publish(record: ActionRecord, expected_revision: number): Promise<PublishResult> {
    await this.#ready();
    const current = (await this.latest(record.digest))?.revision ?? 0;
    if (expected_revision !== current) {
      return { ok: false, reason: "stale", current_revision: current };
    }
    const projected = project(record, current + 1);
    try {
      // Spread into a fresh object: the driver adds _id to the inserted document.
      await this.#revisions.insertOne({ ...projected });
    } catch (error) {
      if ((error as { code?: number }).code !== DUPLICATE_KEY) {
        throw error;
      }
      return { ok: false, reason: "stale", current_revision: (await this.latest(record.digest))?.revision ?? 0 };
    }
    return { ok: true, revision: projected.revision };
  }

  async latest(digest: string): Promise<ProjectedAction | null> {
    if (typeof digest !== "string") {
      return null;
    }
    await this.#ready();
    const document = await this.#revisions.findOne({ digest }, { sort: { revision: -1 }, projection: { _id: 0 } });
    return document ? project(document, document.revision) : null;
  }

  async history(digest: string): Promise<readonly ProjectedAction[]> {
    if (typeof digest !== "string") {
      return [];
    }
    await this.#ready();
    const documents = await this.#revisions.find({ digest }, { sort: { revision: 1 }, projection: { _id: 0 } }).toArray();
    return documents.map((document) => project(document, document.revision));
  }

  async inScope(network_scope: string): Promise<readonly ProjectedAction[]> {
    await this.#ready();
    const documents = await this.#revisions
      .aggregate<ProjectedAction>([
        { $match: { "proposal.network_scope": String(network_scope) } },
        { $sort: { digest: 1, revision: -1 } },
        { $group: { _id: "$digest", latest: { $first: "$$ROOT" } } },
        { $replaceRoot: { newRoot: "$latest" } },
        { $sort: { "proposal.created_at": 1, digest: 1 } },
        { $project: { _id: 0 } },
      ])
      .toArray();
    return documents.map((document) => project(document, document.revision));
  }

  #ready(): Promise<unknown> {
    this.#indexes ??= Promise.all([
      this.#revisions.createIndex({ digest: 1, revision: 1 }, { unique: true }),
      this.#revisions.createIndex({ "proposal.network_scope": 1, digest: 1 }),
    ]).catch((error: unknown) => {
      this.#indexes = null;
      throw error;
    });
    return this.#indexes;
  }
}
