// Must fire: rg-process-spawn-outside-allowlist (import), rg-no-shell (namespace exec)
import * as cp from "child_process";

export const run = (domain: string) => cp.execSync(`dig ${domain}`);
