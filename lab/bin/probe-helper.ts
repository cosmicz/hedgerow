// Loopback-only DNS probe helper for the hybrid topology (Pi-hosted Hedgerow agent,
// Mac-hosted lab). Listens on 127.0.0.1:8777; a Pi reaches it only through an SSH
// reverse tunnel. GET /resolve?name=<lab name>&client=<client|client2> runs the lab's
// dnsq.sh from the owned client container and returns the first A address.
// Allowlisted names and clients only; no other endpoint; no state.
import { join } from "node:path";
const LAB_DIR = join(import.meta.dir, "..");
const RESOLVER = "10.77.0.53";
const background: string[] = JSON.parse(await Bun.file(join(LAB_DIR, "traffic-domains.json")).text()).domains;
const NAMES = new Set(["update-check.cloudsyncapi.net", "wikipedia.org", "endpoint.lab.test", "never.invalid", "example.com", ...background]);
const CLIENTS = new Set(["client", "client2"]);
const PORT = Number(process.env.RG_PROBE_PORT ?? 8777);

async function resolve(name: string, client: string): Promise<string> {
  const proc = Bun.spawn(["sh", join(LAB_DIR, "test/dnsq.sh"), name, RESOLVER, client], { stdout: "pipe", stderr: "ignore" });
  const timer = setTimeout(() => proc.kill(), 6_000);
  try {
    const [text, code] = await Promise.all([new Response(proc.stdout).text(), proc.exited]);
    return code === 0 ? text.trim() : "";
  } finally { clearTimeout(timer); }
}

Bun.serve({
  hostname: "127.0.0.1", port: PORT, idleTimeout: 30, maxRequestBodySize: 0,
  async fetch(req) {
    const url = new URL(req.url);
    if (req.method !== "GET" || url.pathname !== "/resolve") return new Response("not found", { status: 404 });
    const name = url.searchParams.get("name") ?? ""; const client = url.searchParams.get("client") ?? "client";
    if (!NAMES.has(name) || !CLIENTS.has(client)) return new Response("outside lab allowlist", { status: 400 });
    const address = await resolve(name, client);
    return Response.json({ name, client, resolver: RESOLVER, address, checked_at: Date.now(), mode: "live", scope: "lab:rg-lab", via: "mac-probe-helper" });
  },
});
console.log(`probe-helper on 127.0.0.1:${PORT} (lab ${LAB_DIR})`);
