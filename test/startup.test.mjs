import path from "node:path";
import { existsSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";

// Simulate dsh's process.argv[1] pointing to the dsh CLI entry
const dshBin = path.join(process.env.APPDATA, "npm", "node_modules", "@deepseek-ai", "dsh", "lib", "bin.js");
process.argv[1] = dshBin;

test("plugin module graph loads with host-style argv", async () => {
  const mod = await import("../lib/index.js");
  assert.ok(mod.apply, "apply export present");
  assert.equal(mod.apply.constructor.name, "AsyncFunction", "apply is async");
});

test("host.js resolves dsh install root and host packages", async () => {
  const { findDshInstallRoot, hostResolve } = await import("../lib/host.js");
  const root = findDshInstallRoot();
  assert.ok(root, "install root found");
  if (!existsSync(dshBin)) return; // dsh 未安装环境跳过深度解析
  for (const pkg of [
    "@deepseek-ai/cordis-plugin-loader",
    "@deepseek-ai/dsh-tools",
    "@deepseek-ai/dsh-settings",
    "@deepseek-ai/schemastery"
  ]) {
    const url = hostResolve(pkg);
    assert.ok(url, pkg + " resolved");
  }
});
