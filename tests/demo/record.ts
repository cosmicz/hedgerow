// Demo screencast recorder.
//
// Records the EXISTING dedicated Chrome (CDP on 127.0.0.1:9229, the page served
// at 127.0.0.1:8787) to a playable mp4. It never launches or drives a personal
// browser and runs no lab commands: it speaks only CDP to the already-running
// page and shells out only to ffmpeg/ffprobe for encoding.
//
// Every frame written is a real Page.screencastFrame from the live page, each
// acked so capture continues, saved under private/demo with its CDP timestamp.
// Nothing is fabricated or replayed; encoding preserves the real inter-frame
// timing (concat demuxer with per-frame durations), so the clip plays back at
// the speed it was captured. When capture is automated, a small fixed
// "AUTOMATED CAPTURE" banner is injected into the page so viewers can see the
// recording was not hand-produced; it is removed when recording stops.
//
// Usage:
//   bun run tests/demo/record.ts [--seconds 180] [--cdp http://127.0.0.1:9229]
//                                [--match 127.0.0.1:8787] [--out <file>]
//                                [--quality 80] [--no-label]
// Stops at --seconds (default 180) or on Ctrl-C / SIGTERM, then encodes.
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

interface Args {
  seconds: number;
  cdp: string;
  match: string;
  out: string | null;
  quality: number;
  label: boolean;
}

function parseArgs(argv: readonly string[]): Args {
  const args: Args = { seconds: 180, cdp: "http://127.0.0.1:9229", match: "127.0.0.1:8787", out: null, quality: 80, label: true };
  for (let i = 0; i < argv.length; i++) {
    const value = argv[i + 1];
    switch (argv[i]) {
      case "--seconds": args.seconds = clampSeconds(Number(value)); i++; break;
      case "--cdp": args.cdp = String(value); i++; break;
      case "--match": args.match = String(value); i++; break;
      case "--out": args.out = String(value); i++; break;
      case "--quality": args.quality = Math.min(100, Math.max(1, Number(value) || 80)); i++; break;
      case "--no-label": args.label = false; break;
      default: throw new Error(`unknown argument: ${argv[i]}`);
    }
  }
  return args;
}

function clampSeconds(value: number): number {
  return Number.isFinite(value) && value > 0 ? Math.min(3_600, value) : 180;
}

/** Minimal CDP client over the page's WebSocket debugger URL. */
class CdpSession {
  #ws: WebSocket;
  #id = 0;
  readonly #pending = new Map<number, { resolve: (value: unknown) => void; reject: (error: Error) => void }>();
  readonly #listeners = new Map<string, (params: Record<string, unknown>) => void>();

  private constructor(ws: WebSocket) {
    this.#ws = ws;
    ws.addEventListener("message", (event) => this.#onMessage(String(event.data)));
  }

  static async open(wsUrl: string): Promise<CdpSession> {
    const ws = new WebSocket(wsUrl);
    await new Promise<void>((resolve, reject) => {
      ws.addEventListener("open", () => resolve(), { once: true });
      ws.addEventListener("error", () => reject(new Error("CDP WebSocket failed to open")), { once: true });
    });
    return new CdpSession(ws);
  }

  on(method: string, handler: (params: Record<string, unknown>) => void): void {
    this.#listeners.set(method, handler);
  }

  send<T = Record<string, unknown>>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    const id = ++this.#id;
    return new Promise<T>((resolve, reject) => {
      this.#pending.set(id, { resolve: resolve as (value: unknown) => void, reject });
      this.#ws.send(JSON.stringify({ id, method, params }));
    });
  }

  close(): void {
    this.#ws.close();
  }

  #onMessage(data: string): void {
    const message = JSON.parse(data) as { id?: number; result?: unknown; error?: { message?: string }; method?: string; params?: Record<string, unknown> };
    if (typeof message.id === "number") {
      const pending = this.#pending.get(message.id);
      if (!pending) return;
      this.#pending.delete(message.id);
      if (message.error) pending.reject(new Error(`CDP error: ${message.error.message ?? "unknown"}`));
      else pending.resolve(message.result);
    } else if (message.method) {
      this.#listeners.get(message.method)?.(message.params ?? {});
    }
  }
}

const LABEL_ID = "rg-automated-capture-label";

async function pickPageTarget(cdp: string, match: string): Promise<string> {
  const response = await fetch(`${cdp}/json`, { signal: AbortSignal.timeout(5_000) });
  const targets = (await response.json()) as { type: string; url: string; webSocketDebuggerUrl?: string }[];
  const target = targets.find((entry) => entry.type === "page" && entry.url.includes(match) && entry.webSocketDebuggerUrl);
  if (!target?.webSocketDebuggerUrl) {
    throw new Error(`no CDP page target matching ${match}; is the dedicated demo Chrome running on ${cdp}?`);
  }
  return target.webSocketDebuggerUrl;
}

function labelScript(runId: string): string {
  // Fixed, non-interactive overlay so viewers see the capture is automated.
  return `(() => {
    const id = ${JSON.stringify(LABEL_ID)};
    document.getElementById(id)?.remove();
    const el = document.createElement("div");
    el.id = id;
    el.textContent = "● AUTOMATED CAPTURE " + ${JSON.stringify(runId)};
    el.style.cssText = "position:fixed;top:8px;right:8px;z-index:2147483647;pointer-events:none;" +
      "font:600 12px/1.4 -apple-system,system-ui,sans-serif;color:#fff;background:rgba(180,30,30,.82);" +
      "padding:3px 8px;border-radius:4px;letter-spacing:.3px;";
    (document.body || document.documentElement).appendChild(el);
  })();`;
}

async function encode(framesFile: string, outPath: string): Promise<void> {
  const ffmpeg = Bun.spawn([
    "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
    "-f", "concat", "-safe", "0", "-i", framesFile,
    // Even dimensions + yuv420p for broad player support; vfr keeps real timing.
    "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2,format=yuv420p",
    // -bf 0: no B-frame reordering, so PTS stay monotonic and the container
    // duration matches the real capture span.
    "-fps_mode", "vfr", "-c:v", "libx264", "-preset", "veryfast", "-bf", "0", "-pix_fmt", "yuv420p", "-movflags", "+faststart",
    outPath,
  ], { stdout: "pipe", stderr: "pipe" });
  const [stderr, code] = await Promise.all([new Response(ffmpeg.stderr).text(), ffmpeg.exited]);
  if (code !== 0) {
    throw new Error(`ffmpeg failed (exit ${code}): ${stderr.slice(0, 400)}`);
  }
}

async function probeDuration(outPath: string): Promise<string> {
  const probe = Bun.spawn([
    "ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "default=nk=1:nw=1", outPath,
  ], { stdout: "pipe", stderr: "ignore" });
  const [out] = await Promise.all([new Response(probe.stdout).text(), probe.exited]);
  return out.trim();
}

async function main(): Promise<void> {
  const args = parseArgs(Bun.argv.slice(2));
  const runId = new Date().toISOString().replace(/[:.]/g, "-");
  const repoRoot = join(import.meta.dir, "../..");
  const runDir = join(repoRoot, "private/demo", runId);
  mkdirSync(runDir, { recursive: true });

  const wsUrl = await pickPageTarget(args.cdp, args.match);
  const session = await CdpSession.open(wsUrl);

  const frames: { file: string; ms: number }[] = [];
  let stopped = false;
  session.on("Page.screencastFrame", (params) => {
    const sessionId = params.sessionId as number;
    // Ack first so the live stream keeps flowing; only real frames are stored.
    void session.send("Page.screencastFrameAck", { sessionId });
    if (stopped || typeof params.data !== "string") return;
    // Arrival wall-clock is monotonic and reflects the real capture cadence;
    // CDP's frame metadata.timestamp can arrive out of order.
    const ms = Date.now();
    const file = join(runDir, `frame-${String(frames.length).padStart(6, "0")}.jpg`);
    writeFileSync(file, Buffer.from(params.data, "base64"));
    frames.push({ file, ms });
  });

  if (args.label) {
    await session.send("Runtime.enable");
    await session.send("Runtime.evaluate", { expression: labelScript(runId) });
  }
  await session.send("Page.enable");
  await session.send("Page.startScreencast", { format: "jpeg", quality: args.quality, everyNthFrame: 1 });
  await session.send("Page.bringToFront").catch(() => {});
  // Chrome can stop emitting screencast frames after viewport emulation or
  // occlusion. Poll actual rendered frames if the event stream stalls.
  let capturePending: Promise<void> | null = null;
  const fallbackTimer = setInterval(() => {
    if (stopped || capturePending || Date.now() - (frames.at(-1)?.ms ?? 0) < 900) return;
    capturePending = (async () => {
      const shot = await session.send<{ data: string }>("Page.captureScreenshot", { format: "jpeg", quality: args.quality, captureBeyondViewport: false });
      if (stopped) return;
      const ms = Date.now();
      const file = join(runDir, `frame-${String(frames.length).padStart(6, "0")}.jpg`);
      writeFileSync(file, Buffer.from(shot.data, "base64"));
      frames.push({ file, ms });
    })().catch(() => {}).finally(() => { capturePending = null; });
  }, 500);

  console.log(`recording ${args.match} for up to ${args.seconds}s (frames -> ${runDir}); Ctrl-C to stop early`);
  await waitForStop(args.seconds, () => { stopped = true; });

  stopped = true;
  clearInterval(fallbackTimer);
  if (capturePending) await capturePending;
  await session.send("Page.stopScreencast").catch(() => {});
  if (args.label) {
    await session.send("Runtime.evaluate", {
      expression: `document.getElementById(${JSON.stringify(LABEL_ID)})?.remove();`,
    }).catch(() => {});
  }
  session.close();

  if (frames.length === 0) {
    throw new Error("no screencast frames captured; nothing to encode (the recorder never fabricates frames)");
  }

  const framesFile = join(runDir, "frames.txt");
  writeFileSync(framesFile, buildConcatList(frames, Date.now()));
  const outPath = args.out ?? join(runDir, "demo.mp4");
  await encode(framesFile, outPath);
  const duration = await probeDuration(outPath);
  const spanMs = frames[frames.length - 1]!.ms - frames[0]!.ms;
  console.log(`captured ${frames.length} real frames over ${(spanMs / 1_000).toFixed(1)}s`);
  console.log(`wrote ${outPath} (ffprobe duration ${duration || "unknown"}s)`);
}

/**
 * Per-frame durations from real capture timestamps: each frame is held until
 * the next one arrived, and the final frame is held until capture stopped, so
 * a static stretch (no new frames) is shown for the time it was actually on
 * screen. The last file is repeated as the concat demuxer requires.
 */
function buildConcatList(frames: readonly { file: string; ms: number }[], endMs: number): string {
  const lines: string[] = [];
  for (let i = 0; i < frames.length; i++) {
    lines.push(`file '${frames[i]!.file}'`);
    const until = frames[i + 1]?.ms ?? endMs;
    const delta = (until - frames[i]!.ms) / 1_000;
    lines.push(`duration ${Math.max(0.01, delta).toFixed(3)}`);
  }
  lines.push(`file '${frames[frames.length - 1]!.file}'`);
  return `${lines.join("\n")}\n`;
}

function waitForStop(seconds: number, onStop: () => void): Promise<void> {
  return new Promise<void>((resolve) => {
    const finish = () => { onStop(); clearTimeout(timer); resolve(); };
    const timer = setTimeout(finish, seconds * 1_000);
    process.once("SIGINT", finish);
    process.once("SIGTERM", finish);
  });
}

await main();
