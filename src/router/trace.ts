export type AuthenticationOutcome = "accepted" | "rejected";
export type AuthenticationAttemptName = "unrelated-credential" | "old-credential-before-rotation" | "old-credential-after-rotation" | "replacement-credential-after-rotation";

export interface AuthenticationAttempt { readonly attempt: AuthenticationAttemptName; readonly outcome: AuthenticationOutcome; readonly occurred_at: string; }
export interface CredentialRotationTraceInput { readonly target_id: string; readonly evidence_revision: string; readonly attempts: readonly AuthenticationAttempt[]; }
export interface CredentialRotationTrace extends CredentialRotationTraceInput { readonly classification: "lab-only-credential-abuse"; }

const requiredAttempts: readonly [AuthenticationAttemptName, AuthenticationOutcome][] = [
  ["unrelated-credential", "rejected"],
  ["old-credential-before-rotation", "accepted"],
  ["old-credential-after-rotation", "rejected"],
  ["replacement-credential-after-rotation", "accepted"],
];

export function credentialRotationTrace(input: CredentialRotationTraceInput): CredentialRotationTrace {
  if (input.target_id !== "cyber26-openwrt-lab") throw new Error("trace is outside the fixed router lab scope");
  if (!/^sha256:[a-f0-9-]+$/.test(input.evidence_revision)) throw new Error("trace evidence revision is invalid");
  if (input.attempts.length !== requiredAttempts.length) throw new Error("trace must include every authentication attempt");
  let previousTimestamp = "";
  input.attempts.forEach((actual, index) => {
    const [attempt, outcome] = requiredAttempts[index] ?? [];
    if (actual.attempt !== attempt) throw new Error("trace authentication attempt order is invalid");
    if (actual.outcome !== outcome) throw new Error("trace authentication outcome is invalid");
    if (!isTimestamp(actual.occurred_at) || actual.occurred_at <= previousTimestamp) throw new Error("trace authentication timestamp is invalid");
    previousTimestamp = actual.occurred_at;
  });
  return { ...input, classification: "lab-only-credential-abuse" };
}

function isTimestamp(value: string): boolean {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}
