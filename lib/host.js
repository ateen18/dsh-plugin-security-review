import { createRequire } from "node:module";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

/**
 * Host package resolution for dsh-plugin-security-review.
 *
 * The plugin's runtime imports packages that live inside the dsh
 * installation (`@deepseek-ai/cordis-plugin-loader`, `@deepseek-ai/dsh-tools`,
 * `@deepseek-ai/dsh-settings`, `@deepseek-ai/schemastery`). When the plugin is
 * loaded as a local folder (dev install) or linked into a profile, plain ESM
 * bare-specifier resolution cannot find them, because the plugin sits outside
 * any node_modules tree that contains them (the plugin's own `dependencies`
 * are only a fallback).
 *
 * This module locates the dsh install root from the running CLI entry
 * (process.argv[1]) and re-imports the host's own copy of the package, so the
 * module instance — and any class identity the host relies on (e.g. the
 * `EntryTree` class this plugin patches, or the schemastery schema objects the
 * settings system validates) — is shared with the host.
 */

const importCache = new Map();

function realpathSafe(p) {
  try { return realpathSync(p); } catch { return p; }
}

function packageNameOf(dir) {
  try {
    return JSON.parse(readFileSync(path.join(dir, "package.json"), "utf8")).name ?? null;
  } catch {
    return null;
  }
}

/** 桌面客户端内置运行时的包名（app.asar 根 package.json）。 */
const DESKTOP_RUNTIME_NAME = "@deepseek-ai/dsh-desktop-runtime";

/**
 * 把一个候选目录识别成 dsh 运行时描述。
 * @param dir - 候选目录：可能是 dsh 包目录，也可能是桌面运行时的根目录。
 * @returns 运行时描述，或 null。
 */
function runtimeAt(dir) {
  if (!dir) return null;
  const name = packageNameOf(dir);
  if (name === DESKTOP_RUNTIME_NAME) {
    const dshDir = path.join(dir, "node_modules", "@deepseek-ai", "dsh");
    if (packageNameOf(dshDir) !== "@deepseek-ai/dsh") return null;
    return { dshDir, runtimeRoot: dir, packaged: /\.asar([\\/]|$)/i.test(dir) };
  }
  if (name === "@deepseek-ai/dsh") {
    return { dshDir: dir, runtimeRoot: path.resolve(dir, "..", "..", ".."), packaged: /\.asar([\\/]|$)/i.test(dir) };
  }
  return null;
}

/**
 * 定位正在运行的 dsh 运行时。比只看 `@deepseek-ai/dsh` 多认一种布局：
 * 桌面客户端把整套运行时放在 `app.asar/dsh`（package.json 名
 * `@deepseek-ai/dsh-desktop-runtime`），dsh 包在它的 node_modules 下。
 *
 * 解析顺序：
 *   1. DSH_INSTALL_ROOT 覆盖（dsh 包目录或桌面运行时根目录均可）
 *   2. 从 process.argv[1]（宿主启动的 CLI 入口）向上找
 *   3. 从本插件位置解析 "@deepseek-ai/dsh"
 *   4. 从本插件位置解析 "@deepseek-ai/dsh-desktop-runtime"
 *
 * @returns `{dshDir, runtimeRoot, packaged}`，找不到时 null。
 */
export function findDshRuntime() {
  if (process.env.DSH_INSTALL_ROOT) {
    const override = realpathSafe(process.env.DSH_INSTALL_ROOT);
    const found = runtimeAt(override);
    if (found) return found;
  }
  const entry = typeof process.argv[1] === "string" ? process.argv[1] : null;
  if (entry) {
    let dir = path.dirname(path.resolve(entry));
    for (let i = 0; i < 60; i++) {
      const found = runtimeAt(realpathSafe(dir)) ?? runtimeAt(dir);
      if (found) return found;
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  for (const spec of ["@deepseek-ai/dsh/package.json", DESKTOP_RUNTIME_NAME + "/package.json"]) {
    try {
      const req = createRequire(import.meta.url);
      const found = runtimeAt(realpathSafe(path.dirname(req.resolve(spec))));
      if (found) return found;
    } catch {}
    try {
      const url = import.meta.resolve(spec, import.meta.url);
      if (url.startsWith("file:")) {
        const found = runtimeAt(path.dirname(fileURLToPath(url)));
        if (found) return found;
      }
    } catch {}
  }
  return null;
}

/**
 * 宿主包所在的 node_modules 根目录：dsh 包自带 node_modules（pnpm 嵌套布局）
 * 就用它，否则用运行时根的 node_modules（桌面打包布局是提升到根上的）。
 * @param runtime - {@link findDshRuntime} 的结果。
 */
export function hostNodeModulesRoot(runtime) {
  if (!runtime) return null;
  const own = path.join(runtime.dshDir, "node_modules");
  if (existsSync(own)) return own;
  return path.join(runtime.runtimeRoot, "node_modules");
}

/**
 * 定位「官方包」的判定根：打包运行时用运行时根（`app.asar/dsh`，官方包都在
 * 它的 node_modules 下），普通安装用 dsh 包目录（沿用历史语义）。
 *
 * 这个值用于 `gateState.dshInstallRoot`：落在它下面的包视为 dsh 自带、免审。
 * @returns 绝对路径，找不到时 null。
 */
export function findDshInstallRoot() {
  const runtime = findDshRuntime();
  if (!runtime) return null;
  return runtime.packaged ? runtime.runtimeRoot : runtime.dshDir;
}

/**
 * Resolve a host package to an absolute file:// URL. Prefers the copy inside
 * the dsh installation (same module instance the host uses); falls back to
 * ordinary resolution from this plugin's own location.
 *
 * Resolution is anchored with createRequire at a synthetic file inside the
 * dsh install's node_modules, so it follows exactly the layout the host's
 * own module graph sees. When the package ships a separate ESM build
 * (exports["."].import, e.g. @deepseek-ai/schemastery ships .mjs for import
 * and .cjs for require), the ESM entry is preferred so the imported module
 * instance is the same one the host uses.
 */
export function hostResolve(specifier) {
  const runtime = findDshRuntime();
  const nodeModulesRoot = hostNodeModulesRoot(runtime);
  if (nodeModulesRoot) {
    try {
      const req = createRequire(path.join(nodeModulesRoot, "__dsh_plugin_anchor__.js"));
      const resolved = realpathSafe(req.resolve(specifier));
      const url = esmEntryOf(resolved) ?? resolved;
      return pathToFileURL(url).href;
    } catch {}
  }
  try {
    return import.meta.resolve(specifier, import.meta.url);
  } catch {}
  return null;
}

function packageDirOf(entryFile) {
  let dir = path.dirname(entryFile);
  for (let i = 0; i < 10; i++) {
    if (packageNameOf(dir) !== null) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
  return null;
}

/**
 * If the package exposes a dedicated ESM build via exports["."].import,
 * return its realpathed entry file; otherwise null (the require-resolved
 * entry is already the file the host's ESM import uses).
 */
function esmEntryOf(entryFile) {
  const pkgDir = packageDirOf(entryFile);
  if (!pkgDir) return null;
  try {
    const pkg = JSON.parse(readFileSync(path.join(pkgDir, "package.json"), "utf8"));
    const dot = pkg.exports?.["."];
    if (!dot || typeof dot !== "object" || typeof dot.import !== "string") return null;
    return realpathSafe(path.resolve(pkgDir, dot.import));
  } catch {
    return null;
  }
}

/**
 * Dynamically import a host package (cached). Returns the module namespace;
 * for packages with a default export, callers use `ns.default`.
 */
export function hostImport(specifier) {
  let pending = importCache.get(specifier);
  if (!pending) {
    pending = (async () => {
      const url = hostResolve(specifier);
      if (!url) {
        throw new Error(
          `security-review: 无法解析宿主包 "${specifier}"（未找到 dsh 安装根目录，且插件自身依赖也不可解析）`
        );
      }
      return import(url);
    })();
    importCache.set(specifier, pending);
  }
  return pending;
}
