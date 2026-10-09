import { createHash } from "node:crypto";

import { observationKinds, observationModes, type Observation, type ObservationKind, type ObservationMode } from "../domain/observation.js";

export interface ExpectedCollector {
  readonly source_id: string;
  readonly network_scope: string;
  readonly mode: ObservationMode;
}

export interface ReplayContext {
  readonly evaluated_at: string;
  readonly expected_collectors: readonly ExpectedCollector[];
  readonly max_age_ms: Readonly<Record<ObservationKind, number>>;
}

interface ParsedFixture {
  readonly event_id: string;
  readonly observed_at: string;
  readonly received_at: string;
  readonly source_id: string;
  readonly network_scope: string;
  readonly kind: ObservationKind;
  readonly evidence_ref: string;
  readonly mode: ObservationMode;
  readonly payload: Readonly<Record<string, unknown>>;
}

export function validateReplayContext(context: ReplayContext): void {
  parseTimestamp(context.evaluated_at, "evaluated_at");

  for (const collector of context.expected_collectors) {
    requireString(collector.source_id, "expected collector source_id");
    requireString(collector.network_scope, "expected collector network_scope");
    if (!isMode(collector.mode)) {
      throw new TypeError("expected collector mode is invalid");
    }
  }

  for (const kind of observationKinds) {
    const maxAge = context.max_age_ms[kind];
    if (!Number.isSafeInteger(maxAge) || maxAge < 0) {
      throw new TypeError(`max_age_ms.${kind} must be a non-negative integer`);
    }
  }
}

export function normalizeFixture(raw: unknown, context: ReplayContext): Observation {
  validateReplayContext(context);
  const fixture = parseFixture(raw);
  const observedAt = parseTimestamp(fixture.observed_at, "observed_at");
  parseTimestamp(fixture.received_at, "received_at");
  const evaluatedAt = parseTimestamp(context.evaluated_at, "evaluated_at");
  const age = evaluatedAt - observedAt;
  const freshness = age >= 0 && age <= context.max_age_ms[fixture.kind] ? "fresh" : "stale";
  const evidenceRevision = digest(canonicalJson(fixture));

  return {
    id: `observation:${evidenceRevision}`,
    evidence_revision: evidenceRevision,
    observed_at: fixture.observed_at,
    received_at: fixture.received_at,
    source_id: fixture.source_id,
    network_scope: fixture.network_scope,
    kind: fixture.kind,
    evidence_ref: fixture.evidence_ref,
    mode: fixture.mode,
    freshness,
    payload: fixture.payload,
  };
}

export function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function parseFixture(raw: unknown): ParsedFixture {
  const record = requireRecord(raw, "fixture");
  if (record.fixture_type === "pihole-query-fixture") {
    return parsePiHoleFixture(record);
  }

  const fixture = parseCommonFixture(record, requireKind(record.kind), requireRecord(record.payload, "payload"));
  validatePayload(fixture.kind, fixture.payload);
  return fixture;
}

function parsePiHoleFixture(record: Record<string, unknown>): ParsedFixture {
  const query = requireRecord(record.query, "Pi-hole-shaped query");
  const groupIds = requireStringArray(query.group_ids, "Pi-hole-shaped query group_ids");
  const payload = {
    domain: requireString(query.domain, "Pi-hole-shaped query domain"),
    client: requireString(query.client, "Pi-hole-shaped query client"),
    status: requireString(query.status, "Pi-hole-shaped query status"),
    reply: requireString(query.reply, "Pi-hole-shaped query reply"),
    group_ids: groupIds,
    fixture_label: "unverified-pihole-shaped-fixture",
  };

  return parseCommonFixture(record, "dns_query", payload);
}

function parseCommonFixture(
  record: Record<string, unknown>,
  kind: ObservationKind,
  payload: Readonly<Record<string, unknown>>,
): ParsedFixture {
  const fixture = {
    event_id: requireString(record.event_id, "event_id"),
    observed_at: requireString(record.observed_at, "observed_at"),
    received_at: requireString(record.received_at, "received_at"),
    source_id: requireString(record.source_id, "source_id"),
    network_scope: requireString(record.network_scope, "network_scope"),
    kind,
    evidence_ref: requireString(record.evidence_ref, "evidence_ref"),
    mode: requireMode(record.mode),
    payload,
  };
  parseTimestamp(fixture.observed_at, "observed_at");
  parseTimestamp(fixture.received_at, "received_at");
  return fixture;
}

function validatePayload(kind: ObservationKind, payload: Readonly<Record<string, unknown>>): void {
  if (kind === "dns_query") {
    requireString(payload.domain, "DNS payload domain");
  }
  if (kind === "collector_status" || kind === "service_status") {
    if (typeof payload.available !== "boolean") {
      throw new TypeError(`${kind} payload available must be boolean`);
    }
  }
}

function requireKind(value: unknown): ObservationKind {
  if (typeof value !== "string" || !observationKinds.includes(value as ObservationKind)) {
    throw new TypeError("fixture kind is invalid");
  }
  return value as ObservationKind;
}

function requireMode(value: unknown): ObservationMode {
  if (typeof value !== "string" || !isMode(value)) {
    throw new TypeError("fixture mode is invalid");
  }
  return value;
}

function isMode(value: string): value is ObservationMode {
  return observationModes.includes(value as ObservationMode);
}

function requireRecord(value: unknown, name: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value;
}

function requireStringArray(value: unknown, name: string): readonly string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || item.length === 0)) {
    throw new TypeError(`${name} must be an array of non-empty strings`);
  }
  return value;
}

function parseTimestamp(value: string, name: string): number {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new TypeError(`${name} must be an ISO-8601 UTC timestamp`);
  }
  return timestamp;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  throw new TypeError("fixture contains a non-JSON value");
}
