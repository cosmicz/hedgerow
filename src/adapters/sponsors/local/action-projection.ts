// In-process fallback for the MongoDB action projection. Same CAS semantics,
// not durable: history is lost on restart, which the sponsor status discloses.
import { DETAIL_LIMIT, type ActionProjection, type ActionRecord, type ProjectedAction, type PublishResult } from "../types.js";

export class LocalActionProjection implements ActionProjection {
  readonly backend = "local" as const;
  readonly durable = false;
  readonly #revisions = new Map<string, ProjectedAction[]>();

  // Check and append happen in one synchronous step, so concurrent callers in
  // this process cannot both claim the same revision.
  async publish(record: ActionRecord, expected_revision: number): Promise<PublishResult> {
    const revisions = this.#revisions.get(record.digest) ?? [];
    const current = revisions.at(-1)?.revision ?? 0;
    if (expected_revision !== current) {
      return { ok: false, reason: "stale", current_revision: current };
    }
    const projected = project(record, current + 1);
    this.#revisions.set(record.digest, [...revisions, projected]);
    return { ok: true, revision: projected.revision };
  }

  /**
   * Records a revision another backend already accepted, so this copy can take
   * over at the same revision if that backend fails. Older revisions are ignored.
   */
  mirror(projected: ProjectedAction): void {
    const revisions = this.#revisions.get(projected.digest) ?? [];
    if (projected.revision > (revisions.at(-1)?.revision ?? 0)) {
      this.#revisions.set(projected.digest, [...revisions, projected]);
    }
  }

  async latest(digest: string): Promise<ProjectedAction | null> {
    return this.#revisions.get(digest)?.at(-1) ?? null;
  }

  async history(digest: string): Promise<readonly ProjectedAction[]> {
    return this.#revisions.get(digest) ?? [];
  }

  async inScope(network_scope: string): Promise<readonly ProjectedAction[]> {
    return [...this.#revisions.values()]
      .flatMap((revisions) => revisions.at(-1) ?? [])
      .filter((entry) => entry.proposal.network_scope === network_scope)
      .sort((a, b) => a.proposal.created_at - b.proposal.created_at || a.digest.localeCompare(b.digest));
  }
}

export function project(record: ActionRecord, revision: number): ProjectedAction {
  return {
    digest: record.digest,
    proposal: record.proposal,
    status: record.status,
    approved_by: record.approved_by,
    verification: record.verification,
    detail: record.detail.slice(0, DETAIL_LIMIT),
    revision,
  };
}
