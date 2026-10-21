/**
 * 桌面客户端（Electron）运行时探测。
 *
 * dsh 桌面客户端把运行时打包进 Electron 的 `app.asar`，用这份内置运行时启动一个
 * 本机 HTTP 宿主，并固定使用 `desktop` profile。相对 web 版（npm 安装的 dsh CLI），
 * 插件侧有三处硬差异：
 *
 *   1. 运行时目录位于 `app.asar` 内，只读——不能像 web 那样改写 dsh 的 `lib/bin.js`
 *      来让 `dsh plugin add` 走预审（install-gate 在桌面端不可用）；
 *   2. `PATH` 上没有 `dsh` / `pnpm`，包操作必须走启动器注入的
 *      `profileContext.packageManager`，或者内建的 `pluginManager` 服务；
 *   3. profile 目录、安装锚点由启动器以 `profileContext` 服务提供，不应再从
 *      `process.argv[1]` 或 `ctx.baseUrl` 猜。
 *
 * 本模块只做只读探测、不产生副作用，因此可以在单测里用假 ctx 直接跑。
 */

import path from "node:path";
import { existsSync, realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** 是否运行在 Electron 里（宿主由桌面客户端的 Electron 以 Node 模式拉起）。 */
export function isElectronRuntime() {
  return Boolean(process.versions?.electron);
}

/** 路径是否位于 asar 归档内（打包运行时）。 */
export function isAsarPath(value) {
  return typeof value === "string" && /\.asar([\\/]|$)/i.test(value);
}

function realpathSafe(value) {
  try {
    return realpathSync(value);
  } catch {
    return value;
  }
}

/**
 * 读取一个可选服务。cordis 4 里服务通过 `ctx.get(name)` 取得；直接属性访问
 * 在没有该服务时会走到代理上，因此这里把两种方式都包在 try 里。
 */
export function getService(ctx, name) {
  if (!ctx) return undefined;
  try {
    if (typeof ctx.get === "function") {
      const viaGet = ctx.get(name);
      if (viaGet !== undefined && viaGet !== null) return viaGet;
    }
  } catch {}
  try {
    return ctx[name];
  } catch {
    return undefined;
  }
}

/**
 * 解析当前 profile 的位置信息。优先用启动器提供的 `profileContext`
 * （桌面端与 0.2.x web 都有），其次退回 `ctx.baseUrl`（0.1.x web）。
 * @param ctx - 插件 apply 拿到的上下文。
 * @returns profile 位置描述；拿不到目录时 `dir` 为 null。
 */
export function resolveProfileContext(ctx) {
  const fromService = getService(ctx, "profileContext");
  if (fromService && typeof fromService.dir === "string") {
    return {
      dir: fromService.dir,
      name: typeof fromService.name === "string" ? fromService.name : path.basename(fromService.dir),
      installAnchor: typeof fromService.installAnchor === "string" ? fromService.installAnchor : null,
      packageManager: fromService.packageManager ?? null,
      source: "profileContext"
    };
  }
  const baseUrl = typeof ctx?.baseUrl === "string" ? ctx.baseUrl : null;
  if (baseUrl && baseUrl.startsWith("file:")) {
    try {
      const dir = realpathSafe(fileURLToPath(baseUrl));
      return {
        dir,
        name: path.basename(dir),
        installAnchor: null,
        packageManager: null,
        source: "baseUrl"
      };
    } catch {}
  }
  return { dir: null, name: null, installAnchor: null, packageManager: null, source: "none" };
}

/**
 * 把启动器注入的包管理器调用方式规范化成 `{command, args, env}`。
 * 桌面端给的是 `{command: <electron>, args: [--expose-internals, pnpm.mjs], env: {...}}`；
 * web 端没有这个注入，退回 PATH 上的 pnpm。
 * @param profile - {@link resolveProfileContext} 的结果。
 */
export function packageManagerInvocation(profile) {
  const pm = profile?.packageManager;
  if (pm && typeof pm.command === "string") {
    return {
      command: pm.command,
      args: Array.isArray(pm.args) ? [...pm.args] : [],
      env: pm.env && typeof pm.env === "object" ? { ...pm.env } : {},
      source: "profileContext"
    };
  }
  return { command: "pnpm", args: [], env: {}, source: "path" };
}

/**
 * `dsh` CLI 的调用方式。web（npm 安装）用 `node <dsh>/lib/bin.js`；
 * 桌面端用内置的 desktop CLI 入口（它再以同样的 packageManager 调 `runCli`），
 * 因为 `app.asar` 内的 bin.js 不能用普通 node 直接跑。
 * @param options - dsh 包目录、是否打包运行时。
 */
export function dshCliInvocation({ dshDir, packaged }) {
  if (!dshDir) return null;
  if (packaged) {
    const cli = path.join(dshDir, "node_modules", "@deepseek-ai", "dsh-desktop-host", "lib", "cli.js");
    const runtimeRoot = path.resolve(dshDir, "..", "..", "..");
    const desktopCli = existsSync(cli)
      ? cli
      : path.join(runtimeRoot, "node_modules", "@deepseek-ai", "dsh-desktop-host", "lib", "cli.js");
    if (!existsSync(desktopCli)) return null;
    return {
      command: process.execPath,
      args: ["--expose-internals", desktopCli],
      env: { ELECTRON_RUN_AS_NODE: "1" },
      source: "desktop-cli"
    };
  }
  const bin = path.join(dshDir, "lib", "bin.js");
  if (!existsSync(bin)) return null;
  return { command: process.execPath, args: [bin], env: {}, source: "cli-bin" };
}

/**
 * install-gate 是否可用。
 *
 * install-gate 的做法是改写 dsh 的 `lib/bin.js` 插入安装前预审钩子。这要求
 * 该文件可写、且存在——打包运行时（app.asar）两条都不满足。桌面端因此必须
 * 显式报告不可用，而不是静默失败或冒险写只读归档。
 * @param options - dsh 包目录、是否打包运行时。
 * @returns `{supported, reason}`；reason 用于 UI 与日志。
 */
export function installGateSupport({ dshDir, packaged }) {
  if (!dshDir) return { supported: false, reason: "runtime-not-found" };
  if (packaged || isAsarPath(dshDir)) return { supported: false, reason: "packaged-runtime" };
  const bin = path.join(dshDir, "lib", "bin.js");
  if (!existsSync(bin)) return { supported: false, reason: "cli-entry-missing" };
  return { supported: true, reason: null };
}

/**
 * 汇总当前运行环境的能力，供 UI 展示与日志使用。
 * @param options - 插件上下文、dsh 包目录、打包运行时标记。
 */
export function describeRuntime({ ctx, dshDir, packaged, installGate }) {
  const profile = resolveProfileContext(ctx);
  const pluginManager = getService(ctx, "pluginManager");
  const webServer = getService(ctx, "webServer");
  return {
    desktop: Boolean(packaged) || isElectronRuntime(),
    electron: isElectronRuntime(),
    packaged: Boolean(packaged),
    dshDir: dshDir ?? null,
    profile: { name: profile.name, dir: profile.dir, source: profile.source },
    services: {
      profileContext: profile.source === "profileContext",
      pluginManager: Boolean(pluginManager?.installBundle),
      webServer: Boolean(webServer?.register)
    },
    installGate: installGate ?? { supported: false, reason: "unknown" },
    packages: pluginManager?.installBundle ? "plugin-manager" : "cli/pnpm"
  };
}
