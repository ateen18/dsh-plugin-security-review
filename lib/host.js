import { createRequire } from "node:module";
import { readFileSync, realpathSync } from "node:fs";
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

/**
 * Locate the running dsh installation root: the directory whose package.json
 * has name "@deepseek-ai/dsh". Resolution order:
 *   1. DSH_INSTALL_ROOT env override (must point at the dsh package dir)
 *   2. walk up from process.argv[1] (the dsh CLI entry the host started)
 *   3. standard resolution of "@deepseek-ai/dsh" from this plugin's own
 *      location (works when the plugin is installed inside the dsh tree or
 *      has dsh as a dependency)
 */
export function findDshInstallRoot() {
  if (process.env.DSH_INSTALL_ROOT) {
    const dir = realpathSafe(process.env.DSH_INSTALL_ROOT);
    if (dir && packageNameOf(dir) === "@deepseek-ai/dsh") return dir;
  }
  const entry = typeof process.argv[1] === "string" ? process.argv[1] : null;
  if (entry) {
    let dir = path.dirname(path.resolve(entry));
    for (let i = 0; i < 60; i++) {
      if (packageNameOf(dir) === "@deepseek-ai/dsh") return dir;
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  try {
    const req = createRequire(import.meta.url);
    const anchor = req.resolve("@deepseek-ai/dsh/package.json");
    return path.dirname(anchor);
  } catch {}
  try {
    const url = import.meta.resolve("@deepseek-ai/dsh/package.json", import.meta.url);
    if (url.startsWith("file:")) return path.dirname(fileURLToPath(url));
  } catch {}
  return null;
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
  const root = findDshInstallRoot();
  if (root) {
    try {
      const req = createRequire(path.join(root, "node_modules", "__dsh_plugin_anchor__.js"));
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
