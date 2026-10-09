// Listener addresses for a TCP port, so the proof can show that sponsor
// services accept loopback connections only. Fixed lsof argv, no shell;
// allowlisted in rg-process-spawn-outside-allowlist.

export interface PortListeners {
  readonly port: number;
  readonly addresses: readonly string[];
  readonly loopback_only: boolean;
}

export async function listenersOn(port: number): Promise<PortListeners> {
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`invalid port ${port}`);
  }
  const child = Bun.spawn(["lsof", "-nP", `-iTCP:${port}`, "-sTCP:LISTEN", "-Fn"], {
    stdout: "pipe",
    stderr: "ignore",
    stdin: "ignore",
  });
  const text = await new Response(child.stdout).text();
  await child.exited;
  // -Fn prints one "n<address>:<port>" line per socket.
  const addresses = [...new Set(text.split("\n").filter((line) => line.startsWith("n")).map((line) => line.slice(1)))].sort();
  return {
    port,
    addresses,
    loopback_only: addresses.length > 0 && addresses.every((address) => /^(127\.0\.0\.1|\[::1\]):\d+$/.test(address)),
  };
}
