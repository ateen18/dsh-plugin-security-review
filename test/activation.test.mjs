import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { resolveTools } from "../lib/tools.js";
import { installRuntimeGuard } from "../lib/runtime-guard.js";

/**
 * 复现 cordis 4 的上下文代理语义：只有 allow 里列出的属性可读，其他属性一律抛
 * `cannot get property "<name>" without inject`。桌面端 0.2.1 就是这么做的——
 * 插件访问未注入的服务时，条目会直接激活失败（"entry did not activate"）。
 */
function cordisLikeContext(services, core = {}) {
  const builtin = ["get", "on", "once", "emit", "effect", "inject", "plugin", "dispose", "baseUrl"];
  const allowed = new Set([...Object.keys(services), ...builtin, ...Object.keys(core)]);
  return new Proxy({}, {
    get(_target, prop) {
      if (typeof prop === "symbol") return undefined;
      if (!allowed.has(prop)) {
        throw new Error(`cannot get property "${String(prop)}" without inject`);
      }
      if (prop === "get") return (name) => services[name];
      if (prop === "effect") return (fn) => { fn(); return () => {}; };
      if (prop === "on" || prop === "once" || prop === "inject") return () => () => {};
      if (prop === "emit") return () => {};
      if (prop in core) return core[prop];
      return services[prop];
    },
    has(_target, prop) {
      return allowed.has(prop);
    }
  });
}

function fakeReact() {
  return {
    createElement: (...args) => ({ type: args[0], props: args[1] }),
    useState: (initial) => [initial, () => {}],
    useEffect: () => {},
    useCallback: (fn) => fn,
    useRef: (value) => ({ current: value })
  };
}

async function loadClientModule() {
  const file = path.join(process.cwd(), "lib", "client.js");
  const registrations = [];
  globalThis.window = {
    __ModuleLoader__: { load: (registration) => registrations.push(registration) },
    confirm: () => true
  };
  // 每次带唯一 query，避免 ESM 模块缓存让第二个用例拿到上一轮的 side effect。
  await import(pathToFileURL(file).href + "?t=" + Date.now() + Math.random());
  assert.equal(registrations.length, 1, "client.js 应注册且只注册一个 factory");
  const registration = registrations[0];
  assert.equal(registration.id, "dsh-plugin-security-review");
  const exports = registration.factory((specifier) => {
    if (specifier === "react") return fakeReact();
    throw new Error("unexpected require: " + specifier);
  });
  return exports;
}

// ---- 客户端激活（本次桌面端崩溃的根因）----

test("client: 在 cordis 式上下文里激活，不触碰未注入的服务", async () => {
  const exports = await loadClientModule();
  const registered = [];
  const slots = {
    inject: (_name, factory) => factory(),
    register: (definition) => {
      registered.push(definition);
      return () => {};
    }
  };
  // 只注入 slots（与 exports.inject 一致）；locale 通过 ctx.get 读取 → undefined。
  const ctx = cordisLikeContext({ slots });
  assert.doesNotThrow(() => exports.apply(ctx));
  assert.equal(registered.length, 1);
  assert.equal(registered[0].name, "settings.section");
  assert.equal(registered[0].id, "security-review");
  assert.equal(typeof registered[0].label(), "string");
  assert.deepEqual(exports.inject, ["slots"]);
});

test("client: locale 服务存在时注册字典并用于标题", async () => {
  const exports = await loadClientModule();
  const registered = [];
  const localeCalls = [];
  const locale = {
    register: (ns, dict) => localeCalls.push([ns, dict]),
    bind: () => (key) => "本地化:" + key
  };
  const slots = {
    inject: (_name, factory) => factory(),
    register: (definition) => {
      registered.push(definition);
      return () => {};
    }
  };
  const ctx = cordisLikeContext({ slots, locale });
  assert.doesNotThrow(() => exports.apply(ctx));
  assert.equal(localeCalls.length, 1);
  assert.equal(localeCalls[0][0], "security-review");
  assert.equal(registered[0].label(), "本地化:nav.title");
});

// ---- 宿主侧可选服务 ----

test("tools: 未注入 tools 时通过 ctx.get 取得，不抛 cannot get property", () => {
  const tools = { register() {} };
  const ctx = cordisLikeContext({ tools });
  assert.equal(resolveTools(ctx), tools);
});

test("tools: 没有 tools 服务时返回 null 而不是抛错", () => {
  const ctx = cordisLikeContext({});
  assert.equal(resolveTools(ctx), null);
});

test("runtime guard: mode=off 时完全不触碰上下文", () => {
  const ctx = cordisLikeContext({});
  assert.doesNotThrow(() => {
    const dispose = installRuntimeGuard(ctx, { mode: "off" });
    assert.equal(typeof dispose, "function");
    dispose();
  });
});

test("runtime guard: mode=log 时通过 ctx.get 安装 guard", () => {
  const installed = [];
  const tools = { guard: (fn) => { installed.push(fn); return () => {}; } };
  const ctx = cordisLikeContext({ tools });
  const logs = [];
  const dispose = installRuntimeGuard(ctx, { mode: "log", log: (level, message) => logs.push([level, message]) });
  assert.equal(installed.length, 1);
  assert.equal(typeof dispose, "function");
  // 干净调用不产生日志（inspectToolCall 无命中）。
  assert.equal(installed[0]({ name: "read", arguments: { path: "a.txt" } }), undefined);
  assert.equal(logs.length, 0);
});
