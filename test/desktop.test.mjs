import path from "node:path";
import os from "node:os";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";

import {
  describeRuntime,
  installGateSupport,
  isAsarPath,
  packageManagerInvocation,
  resolveProfileContext
} from "../lib/desktop.js";
import { findDshRuntime, findDshInstallRoot } from "../lib/host.js";
import {
  loadStoredSettings,
  normalizePolicy,
  policyToSettings,
  sanitizeSettings,
  saveStoredSettings,
  settingsFilePath
} from "../lib/settings.js";
import { createPackageOps } from "../lib/package-ops.js";
import { buildSecurityReviewApi } from "../lib/api.js";

function tempDir(prefix) {
  return mkdtempSync(path.join(os.tmpdir(), prefix + "-"));
}

// ---- profile 位置 ----

test("desktop: profileContext 优先于 baseUrl", () => {
  const ctx = {
    get(name) {
      if (name === "profileContext") {
        return { dir: "C:\\Users\\x\\.dsh\\profiles\\desktop", name: "desktop", installAnchor: "C:\\app\\app.asar\\dsh\\node_modules\\@deepseek-ai\\dsh\\package.json", packageManager: { command: "electron.exe", args: ["--expose-internals", "pnpm.mjs"] } };
      }
      return undefined;
    },
    baseUrl: "file:///C:/somewhere/else/"
  };
  const profile = resolveProfileContext(ctx);
  assert.equal(profile.source, "profileContext");
  assert.equal(profile.name, "desktop");
  assert.ok(profile.packageManager, "packageManager 透传");
});

test("desktop: 没有 profileContext 时退回 baseUrl（web/0.1.x）", () => {
  const dir = tempDir("sr-profile");
  try {
    const ctx = { get: () => undefined, baseUrl: new URL("file://" + dir.split(path.sep).join("/") + "/").href };
    const profile = resolveProfileContext(ctx);
    assert.equal(profile.source, "baseUrl");
    assert.equal(profile.dir, dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("desktop: asar 路径识别", () => {
  assert.equal(isAsarPath("C:\\app\\resources\\app.asar\\dsh\\package.json"), true);
  assert.equal(isAsarPath("/Applications/DSH.app/Contents/Resources/app.asar/dsh"), true);
  assert.equal(isAsarPath("C:\\app\\resources\\dsh"), false);
  assert.equal(isAsarPath(null), false);
});

// ---- install-gate 能力 ----

test("desktop: 打包运行时 install-gate 不可用，且不尝试写盘", () => {
  const support = installGateSupport({ dshDir: "C:\\app\\resources\\app.asar\\dsh\\node_modules\\@deepseek-ai\\dsh", packaged: true });
  assert.equal(support.supported, false);
  assert.equal(support.reason, "packaged-runtime");
});

test("desktop: 常规安装且 bin.js 存在时 install-gate 可用", () => {
  const dir = tempDir("sr-gate");
  try {
    mkdirSync(path.join(dir, "lib"), { recursive: true });
    writeFileSync(path.join(dir, "lib", "bin.js"), "// dsh cli\n");
    assert.deepEqual(installGateSupport({ dshDir: dir, packaged: false }), { supported: true, reason: null });
    assert.equal(installGateSupport({ dshDir: dir, packaged: false, }).supported, true);
    const missing = installGateSupport({ dshDir: path.join(dir, "nope"), packaged: false });
    assert.equal(missing.supported, false);
    assert.equal(missing.reason, "cli-entry-missing");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---- 运行时识别（桌面 layout）----

test("desktop: 能从 @deepseek-ai/dsh-desktop-runtime 布局定位 dsh 包", () => {
  const root = tempDir("sr-runtime");
  const argvBefore = process.argv[1];
  const envBefore = process.env.DSH_INSTALL_ROOT;
  try {
    delete process.env.DSH_INSTALL_ROOT;
    const runtimeRoot = path.join(root, "app.asar", "dsh");
    const dshDir = path.join(runtimeRoot, "node_modules", "@deepseek-ai", "dsh");
    mkdirSync(path.join(dshDir, "lib"), { recursive: true });
    writeFileSync(path.join(runtimeRoot, "package.json"), JSON.stringify({ name: "@deepseek-ai/dsh-desktop-runtime", version: "0.2.1-rc.2" }));
    writeFileSync(path.join(dshDir, "package.json"), JSON.stringify({ name: "@deepseek-ai/dsh", version: "0.2.1-rc.2" }));
    process.argv[1] = path.join(runtimeRoot, "node_modules", "@deepseek-ai", "dsh-desktop-host", "lib", "cli.js");

    const runtime = findDshRuntime();
    assert.ok(runtime, "识别到运行时");
    assert.equal(runtime.dshDir, dshDir);
    assert.equal(runtime.packaged, true);
    // 打包运行时：官方包判定根是运行时根，dsh 包本身在它下面
    assert.equal(findDshInstallRoot(), runtimeRoot);
    assert.ok(dshDir.startsWith(runtimeRoot + path.sep));
  } finally {
    process.argv[1] = argvBefore;
    if (envBefore === undefined) delete process.env.DSH_INSTALL_ROOT;
    else process.env.DSH_INSTALL_ROOT = envBefore;
    rmSync(root, { recursive: true, force: true });
  }
});

test("desktop: 普通安装布局仍然返回 dsh 包目录", () => {
  const root = tempDir("sr-runtime-web");
  const argvBefore = process.argv[1];
  try {
    delete process.env.DSH_INSTALL_ROOT;
    const dshDir = path.join(root, "node_modules", "@deepseek-ai", "dsh");
    mkdirSync(path.join(dshDir, "lib"), { recursive: true });
    writeFileSync(path.join(dshDir, "package.json"), JSON.stringify({ name: "@deepseek-ai/dsh", version: "0.1.0-rc.6" }));
    process.argv[1] = path.join(dshDir, "lib", "bin.js");
    const runtime = findDshRuntime();
    assert.ok(runtime);
    assert.equal(runtime.packaged, false);
    assert.equal(findDshInstallRoot(), dshDir);
  } finally {
    process.argv[1] = argvBefore;
    rmSync(root, { recursive: true, force: true });
  }
});

test("desktop: packageManager 注入被规范化，缺失时退回 pnpm", () => {
  const injected = packageManagerInvocation({ packageManager: { command: "C:\\app\\DSH.exe", args: ["--expose-internals", "pnpm.mjs"], env: { ELECTRON_RUN_AS_NODE: "1" } } });
  assert.equal(injected.command, "C:\\app\\DSH.exe");
  assert.deepEqual(injected.args, ["--expose-internals", "pnpm.mjs"]);
  assert.equal(injected.source, "profileContext");
  const fallback = packageManagerInvocation({ packageManager: null });
  assert.equal(fallback.command, "pnpm");
  assert.equal(fallback.source, "path");
});

test("desktop: describeRuntime 汇总能力面", () => {
  const ctx = {
    get(name) {
      if (name === "profileContext") return { dir: "D:\\x\\.dsh\\profiles\\desktop", name: "desktop" };
      if (name === "pluginManager") return { installBundle() {}, removeBundle() {} };
      if (name === "webServer") return { register() {} };
      return undefined;
    }
  };
  const info = describeRuntime({ ctx, dshDir: "C:\\app\\app.asar\\dsh\\node_modules\\@deepseek-ai\\dsh", packaged: true, installGate: { supported: false, reason: "packaged-runtime" } });
  assert.equal(info.desktop, true);
  assert.equal(info.packaged, true);
  assert.equal(info.services.pluginManager, true);
  assert.equal(info.packages, "plugin-manager");
  assert.equal(info.installGate.supported, false);
});

// ---- 策略持久化 ----

test("settings: 保存 / 读取 / 收敛", () => {
  const root = tempDir("sr-settings");
  try {
    const file = saveStoredSettings(root, { policy: "strict", autoDisable: true, allowlist: ["a", "b"] });
    assert.equal(file, settingsFilePath(root));
    assert.ok(existsSync(file));
    const loaded = loadStoredSettings(root);
    assert.equal(loaded.policy, "strict");
    assert.equal(loaded.autoDisable, true);

    const sanitized = sanitizeSettings({ policy: "bogus", runtimeGuard: "nuke", allowlist: ["x", 42, ""], evil: 1 });
    assert.equal(sanitized.policy, "standard");
    assert.equal(sanitized.runtimeGuard, "off");
    assert.deepEqual(sanitized.allowlist, ["x", "42"]);
    assert.equal("evil" in sanitized, false);

    assert.equal(normalizePolicy({ mode: "strict", autoDisable: true }).mode, "strict");
    assert.equal(normalizePolicy({ policy: "audit-only" }).mode, "audit-only");
    assert.deepEqual(policyToSettings(normalizePolicy({ policy: "strict" })).policy, "strict");

    // 损坏文件不抛错
    writeFileSync(file, "{not json");
    assert.deepEqual(loadStoredSettings(root), {});
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("settings: 策略文件路径落在 $DSH_HOME/security-review 下", () => {
  assert.ok(settingsFilePath("/tmp/home").endsWith(path.join("home", "settings.json")));
});

// ---- 包操作 ----

test("packages: 有 pluginManager 时安装/卸载都走它（不再 spawn）", async () => {
  const calls = [];
  const ctx = {
    get(name) {
      if (name === "pluginManager") {
        return {
          async installBundle(spec, options) {
            calls.push(["install", spec, options]);
            return { application: "applied", changed: true };
          },
          async removeBundle(name) {
            calls.push(["remove", name]);
            return { application: "restart-required", changed: true };
          }
        };
      }
      return undefined;
    }
  };
  const ops = createPackageOps({ ctx, profile: { dir: "D:\\x\\.dsh\\profiles\\desktop", name: "desktop" }, runtime: { dshDir: "C:\\app\\app.asar\\dsh\\node_modules\\@deepseek-ai\\dsh", packaged: true } });
  const installed = await ops.install("dsh-plugin-foo@1.2.3");
  assert.equal(installed.ok, true);
  assert.equal(installed.via, "plugin-manager");
  assert.equal(calls[0][0], "install");
  assert.deepEqual(calls[0][2], { activate: true });

  const removed = await ops.remove("dsh-plugin-foo");
  assert.equal(removed.ok, true);
  assert.equal(removed.requiresRestart, true);
  assert.deepEqual(calls[1], ["remove", "dsh-plugin-foo"]);

  assert.equal(ops.describe().via, "plugin-manager");
});

test("packages: 非法包名直接拒绝，不触达服务", async () => {
  let touched = false;
  const ctx = { get: () => ({ installBundle() { touched = true; }, removeBundle() { touched = true; } }) };
  const ops = createPackageOps({ ctx, profile: { dir: "D:\\x", name: "desktop" }, runtime: null });
  const result = await ops.remove("--registry=http://evil");
  assert.equal(result.ok, false);
  assert.equal(touched, false);
});

test("packages: 安装失败被折叠成 ok:false 而不是抛出", async () => {
  const ctx = { get: () => ({ async installBundle() { return { application: "failed", error: { code: "network" } }; } }) };
  const ops = createPackageOps({ ctx, profile: { dir: "D:\\x", name: "desktop" }, runtime: null });
  const result = await ops.install("dsh-plugin-foo");
  assert.equal(result.ok, false);
  assert.equal(result.errorCode, "network");
});

// ---- HTTP API ----

function fakeResponse() {
  return {
    status: null,
    body: null,
    headers: null,
    writeHead(status, headers) { this.status = status; this.headers = headers; },
    end(body) { this.body = body; }
  };
}

test("api: 路由表覆盖 list/run/review/install/uninstall/settings/capabilities/gate", () => {
  const routes = buildSecurityReviewApi({});
  const paths = routes.map((route) => route.kind + " " + route.path);
  for (const expected of [
    "exact /api/security-review/list",
    "exact /api/security-review/run",
    "exact /api/security-review/review",
    "exact /api/security-review/install",
    "exact /api/security-review/uninstall",
    "exact /api/security-review/settings",
    "exact /api/security-review/capabilities",
    "exact /api/security-review/gate"
  ]) {
    assert.ok(paths.includes(expected), "缺少路由 " + expected);
  }
});

test("api: 同一 (kind,path) 只注册一次（0.2.x webServer 重名会抛错并吞掉后续路由）", () => {
  const routes = buildSecurityReviewApi({});
  const keys = routes.map((route) => route.kind + " " + route.path);
  assert.equal(new Set(keys).size, keys.length, "存在重复路由: " + keys.join(", "));
});

test("api: 同一路径按方法分派，未知方法 405", async () => {
  const routes = buildSecurityReviewApi({
    gateStatus: () => ({ supported: false, enabled: false }),
    gateSet: (enable) => ({ ok: true, enabled: enable })
  });
  const route = routes.find((item) => item.path === "/api/security-review/gate");

  const getRes = fakeResponse();
  await route.handler({ method: "GET", socket: { remoteAddress: "127.0.0.1" } }, getRes);
  assert.equal(getRes.status, 200);
  assert.deepEqual(JSON.parse(getRes.body), { supported: false, enabled: false });

  const req = Object.assign(new (await import("node:events")).EventEmitter(), { method: "POST", socket: { remoteAddress: "127.0.0.1" } });
  const postRes = fakeResponse();
  const pending = route.handler(req, postRes);
  req.emit("data", Buffer.from(JSON.stringify({ enable: true })));
  req.emit("end");
  await pending;
  assert.deepEqual(JSON.parse(postRes.body), { ok: true, enabled: true });

  const delRes = fakeResponse();
  await route.handler({ method: "DELETE", socket: { remoteAddress: "127.0.0.1" } }, delRes);
  assert.equal(delRes.status, 405);
});

test("api: 非回环请求被 403 拒绝", () => {
  const routes = buildSecurityReviewApi({ list: () => ({ rows: [] }) });
  const route = routes.find((item) => item.path === "/api/security-review/list");
  const res = fakeResponse();
  route.handler({ method: "GET", socket: { remoteAddress: "192.168.1.9" } }, res);
  assert.equal(res.status, 403);
  assert.match(res.body, /loopback-only/);
});

test("api: 回环请求返回服务结果", async () => {
  const routes = buildSecurityReviewApi({ list: () => ({ ok: true, rows: [{ name: "x" }] }) });
  const route = routes.find((item) => item.path === "/api/security-review/list");
  const res = fakeResponse();
  await route.handler({ method: "GET", socket: { remoteAddress: "127.0.0.1" } }, res);
  assert.equal(res.status, 200);
  assert.deepEqual(JSON.parse(res.body), { ok: true, rows: [{ name: "x" }] });
});

test("api: settings 的 POST 会把 body.settings 交给服务", async () => {
  let received = null;
  const routes = buildSecurityReviewApi({ updateSettings: (body) => { received = body; return { ok: true }; } });
  const route = routes.find((item) => item.path === "/api/security-review/settings");
  const req = Object.assign(new (await import("node:events")).EventEmitter(), {
    method: "POST",
    socket: { remoteAddress: "127.0.0.1" }
  });
  const res = fakeResponse();
  const pending = route.handler(req, res);
  req.emit("data", Buffer.from(JSON.stringify({ settings: { policy: "strict" } })));
  req.emit("end");
  await pending;
  assert.deepEqual(received, { settings: { policy: "strict" } });
  assert.equal(res.status, 200);
});

// ---- 客户端 bundle 契约 ----

test("client: bundle 注册 id、相对 API 与可选 locale", () => {
  const source = readFileSync(new URL("../lib/client.js", import.meta.url), "utf8");
  assert.match(source, /window\.__ModuleLoader__\.load\(\{\s*\n\s*id: "dsh-plugin-security-review"/);
  assert.match(source, /api\/security-review\//);
  assert.match(source, /document\.baseURI/);
  assert.equal(/fetch\("\/api\//.test(source), false, "不应再使用站点绝对路径（跨载体/端口会失效）");
  assert.match(source, /exports\.inject = \["slots"\]/, "不注入桌面不存在的客户端服务");
  assert.match(source, /locale\?\.register|locale\.register/, "locale 可选注册");
});
