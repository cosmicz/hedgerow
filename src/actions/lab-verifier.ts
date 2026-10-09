import { join } from "node:path";
import type { Proposal, Verification } from "./types";

/** Independent lookup from the owned client, through the lab resolver. */
export function createLabVerifier(labDirectory: string) {
  const resolve = async (domain: string): Promise<string> => {
    if (!["flagged.lab.test", "benign.lab.test"].includes(domain)) throw new Error("Unknown lab target");
    const child = Bun.spawn(["sh", join(labDirectory, "test/dnsq.sh"), domain, "10.77.0.53"], {
      stdout: "pipe", stderr: "ignore",
    });
    const timeout = setTimeout(() => child.kill(), 4_000);
    try {
      const [text, code] = await Promise.all([new Response(child.stdout).text(), child.exited]);
      return code === 0 ? text.trim() : "";
    } finally { clearTimeout(timeout); }
  };
  return async (proposal: Proposal, expected: "blocked" | "resolved"): Promise<Verification> => {
    if (proposal.network_scope !== "lab:rg-lab" || proposal.domain !== "flagged.lab.test") throw new Error("Probe outside lab scope");
    let result: Verification;
    for (let attempt = 0; ; attempt++) {
      const [target, benign] = await Promise.all([resolve(proposal.domain), resolve("benign.lab.test")]);
      result = { target: target === "0.0.0.0" ? "blocked" : target === "10.77.0.80" ? "resolved" : "failed",
        benign: benign === "10.77.0.80" ? "resolved" : "failed", checked_at: Date.now(), mode: "vm-live" };
      if (result.target === expected && result.benign === "resolved" || attempt >= 9) return result;
      // Pi-hole reloads rule changes asynchronously. Retry reads only, never writes.
      await Bun.sleep(250);
    }
  };
}
