import { expect, test } from "bun:test";

test("a pending chat does not disable the rendered undo action", async () => {
  const app = await Bun.file(new URL("../../src/demo/public/app.js", import.meta.url)).text();
  expect(app).toContain("n.disabled=actionBusy");
  expect(app).toContain("byId(\"chat-input\").disabled=chatBusy");
  expect(app).toContain("const isChat=command===\"chat\"");
  expect(app).not.toContain("n.disabled=busy");
});
