// Must fire: rg-no-shell (x3), rg-process-spawn-outside-allowlist (x2)
import { exec } from "node:child_process";

export async function unsafe(domain: string) {
  exec(`pihole -b ${domain}`);
  await Bun.$`pihole -b ${domain}`;
  Bun.spawn(["sh", "-c", domain], { shell: true });
}
