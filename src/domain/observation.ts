export const observationModes = ["synthetic", "replay", "vm-live", "physical-live"] as const;

export type ObservationMode = (typeof observationModes)[number];

export const observationKinds = ["collector_status", "dns_query", "service_status", "wifi_posture"] as const;

export type ObservationKind = (typeof observationKinds)[number];

export type Freshness = "fresh" | "stale";

export interface Observation {
  readonly id: string;
  readonly evidence_revision: string;
  readonly observed_at: string;
  readonly received_at: string;
  readonly source_id: string;
  readonly network_scope: string;
  readonly kind: ObservationKind;
  readonly evidence_ref: string;
  readonly mode: ObservationMode;
  readonly freshness: Freshness;
  readonly payload: Readonly<Record<string, unknown>>;
}
