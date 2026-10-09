// Public sponsor API for the server/UI (cyber26-o1v). Everything else under
// src/adapters/sponsors is an implementation detail or proof tooling.
export {
  ELIGIBILITY,
  SponsorBridge,
  type MirrorReport,
  type MongoBoundaryOptions,
  type RecordResult,
  type Sourced,
  type SponsorBridgeConfig,
  type SponsorBridgeDeps,
  type SponsorEligibility,
  type SponsorReport,
} from "./bridge.js";
export { JournalMirrorError, type JournalSource, type MirroredEvent } from "./journal-mirror.js";
export type { SourcedEvidence } from "./resilient.js";
export { runSemgrep, type SecurityScanEvidence } from "./semgrep/scan.js";
export type { AuditEvent, DomainEvidence, EvidenceQuery, ProjectedAction, SponsorHealth, SponsorStatus } from "./types.js";
export {
  GUIDANCE_QUERIES,
  SensoGuidance,
  readSensoKey,
  type GuidanceDocument,
  type GuidancePassage,
  type GuidanceResult,
  type GuidanceTopic,
  type SensoDeps,
  type SensoStatus,
} from "./senso/index.js";
