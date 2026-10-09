export interface Proposal {
  action: "dns-deny";
  network_scope: string;
  resolver_id: string;
  domain: string;
  group_id: number;
  evidence_revision: string;
  created_at: number;
  expires_at: number;
}
export interface Rule { domain: string; groups: number[]; enabled: boolean; comment: string; }
export interface DnsAdapter {
  read(domain: string): Promise<Rule | null>;
  create(rule: Rule): Promise<void>;
  remove(domain: string): Promise<void>;
}
export interface Verification {
  target: "blocked" | "resolved" | "failed";
  benign: "resolved" | "failed";
  checked_at: number;
  mode: "synthetic" | "replay" | "vm-live" | "physical-live";
}
export type ActionStatus = "proposed" | "approved" | "revoked" | "executing" | "active" |
  "ambiguous" | "conflict" | "failed" | "undoing" | "reverted" | "rollback-unverified";
export interface ActionRecord {
  digest: string;
  proposal: Proposal;
  status: ActionStatus;
  approved_by: string | null;
  verification: Verification | null;
  detail: string;
}
export interface Policy {
  network_scope: string;
  resolver_id: string;
  group_id: number;
  allowed_domains: readonly string[];
  max_duration_ms: number;
}
