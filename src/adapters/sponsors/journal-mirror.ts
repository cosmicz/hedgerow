// Mirrors the action core's durable journal into the sponsor stores.
//
// Source of truth is SqliteLedger: get() for the proposal (put() writes no
// event) and history() for every transition with its journal timestamp and
// verification, including executing and undoing.
//
// The mirror keeps no checkpoint of its own. The journal is append-only and
// ordered by seq, so each event has a fixed projection revision: revision 1
// is the proposal and revision k+1 is the k-th journal event. Every sync()
// reads the durable projection, verifies the revisions already there against
// the events they must be, and publishes only the missing ones. A process
// restart therefore resumes where the durable projection ends. A stale publish
// counts as mirrored only if the stored revision is exactly the expected
// record; anything else throws (fail closed) without advancing.
// Audit events have deterministic ids, and both stores dedupe by id.
import type { ActionEvent, SqliteLedger } from "../../actions/ledger.js";
import { project } from "./local/action-projection.js";
import type { ActionProjection, ActionRecord, ObservationStore, ProjectedAction } from "./types.js";

export interface MirroredEvent {
  readonly seq: number | null;
  readonly status: ActionRecord["status"];
  readonly at: number | null;
  readonly revision: number;
  readonly verification: ActionRecord["verification"];
}

/** The read side of the action journal; SqliteLedger satisfies it. */
export type JournalSource = Pick<SqliteLedger, "get" | "history">;

export class JournalMirrorError extends Error {
  override readonly name = "JournalMirrorError";
}

interface Expected {
  readonly record: ActionRecord;
  readonly event: ActionEvent | null;
  readonly at: number | null;
  readonly revision: number;
}

export class JournalMirror {
  readonly #ledger: JournalSource;
  readonly #projection: ActionProjection;
  readonly #store: ObservationStore;

  constructor(ledger: JournalSource, projection: ActionProjection, store: ObservationStore) {
    this.#ledger = ledger;
    this.#projection = projection;
    this.#store = store;
  }

  /** Brings the projection and audit up to the journal; safe to call any number of times, from any process. */
  async sync(digest: string): Promise<readonly MirroredEvent[]> {
    const expected = this.#expected(digest);
    const stored = await this.#projection.history(digest);
    if (stored.length > expected.length) {
      throw new JournalMirrorError(`projection has ${stored.length} revisions but the journal implies ${expected.length}`);
    }
    for (const entry of expected) {
      const existing = stored.find((revision) => revision.revision === entry.revision);
      if (existing) {
        assertSame(existing, entry);
      } else {
        await this.#publish(entry);
      }
      await this.#audit(entry);
    }
    return expected.map((entry) => ({
      seq: entry.event?.seq ?? null,
      status: entry.record.status,
      at: entry.at,
      revision: entry.revision,
      verification: entry.record.verification,
    }));
  }

  #expected(digest: string): Expected[] {
    const current = this.#ledger.get(digest);
    const proposed: Expected = {
      record: { ...current, status: "proposed", approved_by: null, verification: null, detail: "Proposal recorded" },
      event: null,
      // The proposal is the journal row itself; its only timestamp is the proposal's created_at.
      at: current.proposal.created_at,
      revision: 1,
    };
    // Transitions without a probe keep the last known verification, as the journal's current record does.
    let verification: ActionRecord["verification"] = null;
    const transitions = this.#ledger.history(digest).map((event, index): Expected => {
      verification = event.verification ?? verification;
      return {
        record: {
          digest,
          proposal: current.proposal,
          status: event.status,
          // Approval is set once; every journal event follows it (a revoke before approval leaves it null).
          approved_by: current.approved_by,
          verification,
          detail: event.detail,
        },
        event,
        at: event.at,
        revision: index + 2,
      };
    });
    return [proposed, ...transitions];
  }

  async #publish(entry: Expected): Promise<void> {
    const result = await this.#projection.publish(entry.record, entry.revision - 1);
    if (result.ok && result.revision === entry.revision) {
      return;
    }
    // Another writer may have mirrored the same event concurrently; accept only an exact match.
    const stored = (await this.#projection.history(entry.record.digest)).find((revision) => revision.revision === entry.revision);
    if (!stored) {
      throw new JournalMirrorError(`revision ${entry.revision} (${entry.record.status}) not accepted: ${JSON.stringify(result)}`);
    }
    assertSame(stored, entry);
  }

  #audit(entry: Expected): Promise<void> {
    return this.#store.appendAudit({
      id: `journal:${entry.record.digest}:${String(entry.event?.seq ?? 0).padStart(8, "0")}`,
      // Legacy events without a journal time are marked unknown, not given a fabricated one.
      at: new Date(entry.at ?? entry.record.proposal.created_at).toISOString(),
      subject_id: `journal:${entry.record.digest}`,
      kind: entry.record.status,
      detail: JSON.stringify({
        seq: entry.event?.seq ?? null,
        at_known: entry.at !== null,
        detail: entry.record.detail,
        verification: entry.event ? entry.event.verification : null,
      }),
    });
  }
}

function assertSame(stored: ProjectedAction, entry: Expected): void {
  if (fingerprint(stored) !== fingerprint(project(entry.record, entry.revision))) {
    throw new JournalMirrorError(`projection revision ${entry.revision} is not journal event ${entry.record.status}; refusing to continue`);
  }
}

function fingerprint(entry: ProjectedAction): string {
  return JSON.stringify([
    entry.digest,
    entry.revision,
    entry.status,
    entry.approved_by,
    entry.detail,
    entry.verification && [entry.verification.target, entry.verification.benign, entry.verification.checked_at, entry.verification.mode],
    [
      entry.proposal.action, entry.proposal.network_scope, entry.proposal.resolver_id, entry.proposal.domain,
      entry.proposal.group_id, entry.proposal.evidence_revision, entry.proposal.created_at, entry.proposal.expires_at,
    ],
  ]);
}
