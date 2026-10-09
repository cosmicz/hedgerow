import { createHash } from "node:crypto";
import { chmodSync } from "node:fs";
import { Database } from "bun:sqlite";

export interface CredentialRotationProposal { readonly action_id: string; readonly target_id: string; readonly network_scope: string; readonly image_digest: string; readonly evidence_revision: string; readonly recovery_ref: string; readonly expires_at: string; }
export interface MeasuredPreRotationEvidence { readonly image_id: string; readonly network_internal: true; readonly router_network_mode: string; readonly router_privileged: false; readonly router_port_bindings: false; readonly shadow_revision: string; }
export type ApprovalStatus = "proposed" | "approved" | "executing" | "applied" | "failed" | "ambiguous" | "stale";
export interface Clock { now(): string; }

export function approvalDigest(proposal: CredentialRotationProposal): string { return digest(canonicalJson(proposal)); }
export function measuredEvidenceRevision(evidence: MeasuredPreRotationEvidence): string { return `sha256:${digest(canonicalJson(evidence))}`; }

export class RouterApprovalJournal {
  readonly #db: Database;
  constructor(path: string, readonly clock: Clock) {
    this.#db = new Database(path, { create: true });
    chmodSync(path, 0o600);
    this.#db.exec("CREATE TABLE IF NOT EXISTS router_approvals (digest TEXT PRIMARY KEY, proposal_json TEXT NOT NULL, status TEXT NOT NULL, approved_by TEXT, approved_at TEXT, consumed_at TEXT)");
  }
  close(): void { this.#db.close(); }
  propose(proposal: CredentialRotationProposal): string {
    const digest = approvalDigest(proposal);
    this.#db.query("INSERT OR IGNORE INTO router_approvals (digest, proposal_json, status) VALUES (?, ?, 'proposed')").run(digest, canonicalJson(proposal));
    return digest;
  }
  approve(digest: string, typedPrefix: string, isTty: boolean, operator: string): void {
    if (!isTty) throw new Error("operator approval requires a TTY");
    if (typedPrefix !== digest.slice(0, 8)) throw new Error("operator approval confirmation does not match");
    this.transition(digest, "proposed", "approved", { approved_by: operator, approved_at: this.clock.now() });
  }
  consume(digest: string): CredentialRotationProposal {
    // Approval is consumed once; a transport failure never makes it reusable.
    const row = this.row(digest);
    const proposal = JSON.parse(row.proposal_json) as CredentialRotationProposal;
    if (Date.parse(this.clock.now()) >= Date.parse(proposal.expires_at)) { this.transition(digest, "approved", "failed"); throw new Error("operator approval is expired"); }
    this.transition(digest, "approved", "executing", { consumed_at: this.clock.now() });
    return proposal;
  }
  complete(digest: string, status: "applied" | "failed" | "ambiguous" | "stale"): void { this.transition(digest, "executing", status); }
  status(digest: string): ApprovalStatus { return this.row(digest).status as ApprovalStatus; }
  /** Called only behind the demo's exact Origin/Host/CSRF and selected-digest checks. */
  approveFromUi(digest: string, operator: string): void {
    if (!operator) throw new Error("Human operator required");
    this.transition(digest, "proposed", "approved", { approved_by: operator, approved_at: this.clock.now() });
  }
  private row(digest: string): { proposal_json: string; status: string } { const row = this.#db.query("SELECT proposal_json, status FROM router_approvals WHERE digest = ?").get(digest) as { proposal_json: string; status: string } | null; if (!row) throw new Error("operator approval is not proposed"); return row; }
  private transition(digest: string, from: ApprovalStatus, to: ApprovalStatus, fields: { approved_by?: string; approved_at?: string; consumed_at?: string } = {}): void {
    const result = this.#db.query("UPDATE router_approvals SET status = ?, approved_by = COALESCE(?, approved_by), approved_at = COALESCE(?, approved_at), consumed_at = COALESCE(?, consumed_at) WHERE digest = ? AND status = ?").run(to, fields.approved_by ?? null, fields.approved_at ?? null, fields.consumed_at ?? null, digest, from);
    if (result.changes !== 1) throw new Error(`approval transition ${from} -> ${to} refused`);
  }
}

function digest(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function canonicalJson(value: unknown): string { if (value === null || ["boolean", "number", "string"].includes(typeof value)) return JSON.stringify(value); if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`; if (typeof value === "object") { const record = value as Record<string, unknown>; return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`; } throw new TypeError("non-JSON approval data"); }
