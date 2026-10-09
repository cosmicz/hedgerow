import type { RouterCommand } from "./router";
export type Command = "observe" | "classify" | "propose" | "approve" | "execute" | "undo" | "reset" | "chat" | RouterCommand;
export interface HttpPorts {
  origin: string;
  token: string;
  assets: Readonly<Record<string, { body: string; type: string }>>;
  state(): unknown;
  command(name: Command, input: { digest?: string; message?: string }): Promise<unknown>;
}
const commands: readonly string[] = ["chat", "observe", "classify", "propose", "approve", "execute", "undo", "reset", "router-prepare", "router-attack", "router-classify", "router-propose", "router-approve", "router-execute", "router-cleanup"];
const headers = {
  "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
  "Content-Security-Policy": "default-src 'self'; connect-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
};
function json(value: unknown, status = 200) {
  return Response.json(value, { status, headers });
}
async function body(request: Request): Promise<unknown> {
  const reader = request.body?.getReader();
  if (!reader) throw new Error("body");
  const chunks: Uint8Array[] = []; let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      size += value.byteLength;
      if (size > 4096) { await reader.cancel(); throw new RangeError("size"); }
      chunks.push(value);
    }
    const result = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(result));
  } finally { reader.releaseLock(); }
}
/** Capability boundary: every mutation is same-origin, token-bound and serialized. */
export function createDemoHandler(o: HttpPorts) {
  const origin = new URL(o.origin);
  if (origin.hostname !== "127.0.0.1" || origin.protocol !== "http:" || origin.origin !== o.origin ||
    !/^[a-f0-9]{64}$/.test(o.token)) throw new Error("Explicit local origin and random CSRF token required");
  let busy = false;
  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    if (url.origin !== o.origin || request.headers.get("Host") !== origin.host ||
      ["cross-site", "same-site"].includes(request.headers.get("Sec-Fetch-Site") ?? "") ||
      (request.headers.has("Origin") && request.headers.get("Origin") !== o.origin)) return json({ error: "Local origin required" }, 403);
    if (url.search || url.hash) return json({ error: "Unknown route" }, 404);
    if (request.method === "GET") {
      if (url.pathname === "/api/state") return json(o.state());
      if (url.pathname === "/api/session") return json({ token: o.token });
      const asset = Object.hasOwn(o.assets, url.pathname) ? o.assets[url.pathname] : null;
      return asset ? new Response(asset.body, { headers: { ...headers, "Content-Type": asset.type } }) : json({ error: "Unknown route" }, 404);
    }
    if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);
    if (request.headers.get("Origin") !== o.origin || request.headers.get("X-Hedgerow-CSRF") !== o.token) return json({ error: "Explicit local session required" }, 403);
    const name = url.pathname.slice("/api/".length);
    if (!url.pathname.startsWith("/api/") || !commands.includes(name)) return json({ error: "Unknown route" }, 404);
    if (request.headers.get("Content-Type") !== "application/json") return json({ error: "JSON required" }, 415);
    let input: any;
    try { input = await body(request); }
    catch (error) { return json({ error: "Invalid bounded request" }, error instanceof RangeError ? 413 : 400); }
    const keys = name==="chat"?["message"]:["approve", "execute", "undo", "router-approve", "router-execute"].includes(name) ? ["digest"] : [];
    if (!input || Array.isArray(input) || typeof input !== "object" || Object.keys(input).length !== keys.length ||
      !keys.every(key => Object.hasOwn(input, key)) || (name==="chat" ? typeof input.message!=="string"||input.message.trim().length<1||input.message.length>1000 : keys.length && (typeof input.digest !== "string" || !/^[a-f0-9]{64}$/.test(input.digest)))) return json({ error: "Exact command fields required" }, 400);
    if (busy) return json({ error: "Another operation is running; inspect state before retrying" }, 409);
    busy = true;
    try { return json(await o.command(name as Command, input)); }
    catch { return json({ error: "Operation unavailable or outcome requires inspection; check measured state before retrying" }, 409); }
    finally { busy = false; }
  };
}
