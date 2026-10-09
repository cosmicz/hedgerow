import { mkdirSync } from "node:fs";
import { expect } from "bun:test";
const mobile = process.argv.includes("--mobile");
const recovery = process.argv.includes("--recovery");
const pages: any[] = await (await fetch("http://127.0.0.1:9229/json/list")).json();
const page = pages.find(p => p.type === "page" && p.url === "http://127.0.0.1:8787/");
if (!page || !page.webSocketDebuggerUrl.startsWith("ws://127.0.0.1:9229/")) throw new Error("Dedicated local demo browser required");
const socket = new WebSocket(page.webSocketDebuggerUrl);
await new Promise<void>((resolve, reject) => { socket.onopen = () => resolve(); socket.onerror = () => reject(new Error("Browser connection failed")); });
let seq = 0;
const pending = new Map<number, { resolve: (value: any) => void; reject: (error: Error) => void }>();
socket.onmessage = event => {
  const message = JSON.parse(String(event.data)); const item = pending.get(message.id);
  if (item) { pending.delete(message.id); message.error ? item.reject(new Error("Browser command failed")) : item.resolve(message.result); }
};
const call = (method: string, params: unknown = {}) => new Promise<any>((resolve, reject) => {
  const id = ++seq; pending.set(id, { resolve, reject }); socket.send(JSON.stringify({ id, method, params }));
});
try {
  await call("Runtime.enable");
  if (mobile) await call("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
  if (process.argv.includes("--reload")) { await call("Page.reload", { ignoreCache: true }); await Bun.sleep(1200); }
  if (recovery) {
    await call("Network.enable");
    await call("Network.setBlockedURLs", { urls: ["http://127.0.0.1:8787/api/state"] });
    await Bun.sleep(3500);
    const lost = await call("Runtime.evaluate", { expression: "document.getElementById('message').textContent", returnByValue: true });
    expect(lost.result.value).toContain("unavailable");
    await call("Network.setBlockedURLs", { urls: [] });
    await Bun.sleep(3500);
    const recovered = await call("Runtime.evaluate", { expression: "document.getElementById('message').textContent", returnByValue: true });
    expect(recovered.result.value).toContain("Connection restored");
    console.log("PASS: connection loss and recovery displayed in the real browser");
  }
  const result = await call("Runtime.evaluate", { expression: "JSON.stringify({title:document.title,message:document.getElementById('message').textContent,buttons:[...document.querySelectorAll('button')].map(b=>b.textContent),width:innerWidth,overflow:document.documentElement.scrollWidth>innerWidth})", returnByValue: true });
  console.log(result.result.value);
  expect(JSON.parse(result.result.value).overflow).toBe(false);
  expect(JSON.parse(result.result.value).buttons).toContain("Reset demo view");
  const shot = await call("Page.captureScreenshot", { format: "png", captureBeyondViewport: true });
  mkdirSync("private/demo", { recursive: true, mode: 0o700 });
  const path = `private/demo/browser-${Date.now()}.png`;
  await Bun.write(path, Buffer.from(shot.data, "base64"));
  console.log(path);
} finally {
  if (recovery) await call("Network.setBlockedURLs", { urls: [] });
  if (mobile) await call("Emulation.clearDeviceMetricsOverride");
  socket.close();
}
