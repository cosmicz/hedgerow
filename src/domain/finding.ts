import type { ObservationMode } from "./observation.js";

export type FindingState = "observed" | "unknown";

export interface Coverage {
  readonly state: "observed" | "unknown";
  readonly network_scope: string;
  readonly source_id: string;
  readonly reason: string;
}

export interface Finding {
  readonly id: string;
  readonly rule_id: string;
  readonly state: FindingState;
  readonly evidence_ids: readonly string[];
  readonly evidence_revision: string;
  readonly mode: ObservationMode;
  readonly coverage: Coverage;
  readonly limits: readonly string[];
}
