// Must fire: rg-process-spawn-outside-allowlist. Only lab-verifier.ts is exempt in src/actions.
export const probe = () => Bun.spawn(["dig", "flagged.test"]);
