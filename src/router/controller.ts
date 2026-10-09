import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";

import { RouterApprovalJournal, type CredentialRotationProposal } from "./approval.js";
import { PersistentRouterTransport } from "./persistent.js";
import type { Clock, RouterRunner } from "./runner.js";
import { credentialRotationTrace, type CredentialRotationTrace } from "./trace.js";

export type RouterLabPhase = "down" | "prepared" | "attacked" | "proposed" | "approved" | "rotated" | "failed";
export interface RedactedAuthAttempt { readonly role: "unrelated" | "seeded-before" | "seeded-after" | "replacement"; readonly started_at: string; readonly finished_at: string; readonly outcome: "accepted" | "rejected" | "error"; }
export interface PreparedRouterLab { readonly phase: "prepared"; readonly evidence_revision: string; readonly topology: "internal-docker-only"; readonly runtime: "openwrt-userland-container"; }
export interface RouterLabController {
  prepare(): Promise<PreparedRouterLab>;
  attack(): Promise<{ readonly phase: "attacked"; readonly attempts: readonly RedactedAuthAttempt[]; readonly evidence_revision: string }>;
  propose(): Promise<{ readonly phase: "proposed"; readonly digest: string; readonly expires_at: string; readonly evidence_revision: string; readonly confirmation: string }>;
  approveFromUi(digest: string, operator: string, confirmed: boolean): Promise<{ readonly phase: "approved" }>;
  rotate(digest: string): Promise<{ readonly phase: "rotated"; readonly trace: CredentialRotationTrace }>;
  cleanup(): Promise<{ readonly phase: "down" }>;
}

export interface RouterLabControllerOptions { readonly runner: RouterRunner; readonly now: Clock; readonly privateDirectory: string; }

type Transport = Pick<PersistentRouterTransport, "prepare" | "attack" | "measuredRevision" | "rotateAndVerify" | "cleanup">;
export interface RouterLabControllerOptions {
  readonly runner: RouterRunner; readonly now: Clock; readonly privateDirectory: string;
  /** Application-owned test seam; never constructed from browser or model input. */
  readonly transport?: Transport;
}
export function createRouterLabController(options: RouterLabControllerOptions): RouterLabController {
  mkdirSync(options.privateDirectory, { recursive: true, mode: 0o700 });
  const transport = options.transport ?? new PersistentRouterTransport(options.runner, options.now, options.privateDirectory);
  const journal = new RouterApprovalJournal(`${options.privateDirectory}/approvals.sqlite`, options.now);
  let phase: RouterLabPhase = "down", measured = "", revision = "", observedAt = 0, selected = "";
  let attacks: readonly RedactedAuthAttempt[] = [];
  const timestamp = () => Date.parse(options.now.now());
  const hash = (value: unknown) => `sha256:${createHash("sha256").update(JSON.stringify(value)).digest("hex")}`;
  const eligible = () => timestamp() >= observedAt && timestamp() - observedAt <= 300000 &&
    attacks.length === 2 && attacks[0]?.role === "unrelated" && attacks[0]?.outcome === "rejected" &&
    attacks[1]?.role === "seeded-before" && attacks[1]?.outcome === "accepted";
  const requireCurrent = async () => {
    if (!eligible() || await transport.measuredRevision() !== measured) throw new Error("Router evidence changed or expired");
  };
  return {
    async prepare() {
      if (phase !== "down") throw new Error("Prior lab must be cleaned up");
      try {
        await transport.prepare(); measured = await transport.measuredRevision();
        phase = "prepared"; attacks = []; selected = ""; revision = "";
        return {phase:"prepared",evidence_revision:measured,topology:"internal-docker-only",runtime:"openwrt-userland-container"};
      } catch (error) { phase = "failed"; throw error; }
    },
    async attack() {
      if (phase !== "prepared") throw new Error("Prepare the owned lab first");
      if (await transport.measuredRevision() !== measured) throw new Error("Prepared lab changed");
      attacks = await transport.attack(); observedAt = timestamp();
      await requireCurrent();
      revision = hash({measured, attempts:attacks}); phase = "attacked";
      return {phase:"attacked", attempts:attacks, evidence_revision:revision};
    },
    async propose() {
      if (phase !== "attacked") throw new Error("Fresh measured attack required");
      await requireCurrent();
      const proposal: CredentialRotationProposal = {
        action_id:"router-ui-rotation",target_id:"cyber26-openwrt-lab",network_scope:"cyber26-router-8j3",
        image_digest:"sha256:537d90b97c6f0e99d3ced6af8c0dd1034370ee355ee00332bfa46935b843d767",
        evidence_revision:revision,recovery_ref:"server-private-recovery",
        expires_at:new Date(observedAt + 300000).toISOString(),
      };
      selected = journal.propose(proposal); phase = "proposed";
      return {phase:"proposed",digest:selected,expires_at:proposal.expires_at,evidence_revision:revision,
        confirmation:"Change only the disposable owned lab router password. The old credential will stop working; the replacement stays in server-private recovery storage."};
    },
    async approveFromUi(digest, operator, confirmed) {
      if (!confirmed || digest !== selected || phase !== "proposed") throw new Error("Exact local human confirmation required");
      await requireCurrent();
      journal.approveFromUi(digest, operator); phase = "approved";
      return {phase:"approved"};
    },
    async rotate(digest) {
      if (digest !== selected || phase !== "approved") throw new Error("Exact persisted approval required");
      await requireCurrent();
      const proposal = journal.consume(digest);
      if (proposal.evidence_revision !== revision || proposal.target_id !== "cyber26-openwrt-lab") {
        journal.complete(digest,"stale"); phase="failed"; throw new Error("Approval evidence mismatch");
      }
      try {
        const after = await transport.rotateAndVerify();
        if (after[0]?.role !== "seeded-after" || after[0]?.outcome !== "rejected" ||
          after[1]?.role !== "replacement" || after[1]?.outcome !== "accepted") throw new Error("Independent login checks did not verify rotation");
        const attempts = [...attacks,...after].map((attempt): import("./trace").AuthenticationAttempt => {
          if (attempt.outcome === "error") throw new Error("Authentication transport error");
          return {attempt:attempt.role === "unrelated" ? "unrelated-credential" : attempt.role === "seeded-before" ?
            "old-credential-before-rotation" : attempt.role === "seeded-after" ? "old-credential-after-rotation" :
            "replacement-credential-after-rotation",outcome:attempt.outcome,occurred_at:attempt.finished_at};
        });
        const trace = credentialRotationTrace({target_id:"cyber26-openwrt-lab",evidence_revision:revision,attempts});
        journal.complete(digest,"applied"); phase="rotated";
        return {phase:"rotated",trace};
      } catch { journal.complete(digest,"ambiguous"); phase="failed"; throw new Error("Rotation outcome requires inspection; never replay"); }
    },
    async cleanup() {
      await transport.cleanup(); phase="down"; selected=""; measured=""; revision=""; attacks=[];
      return {phase:"down"};
    },
  };
}
