import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { existsSync, realpathSync, statSync } from "node:fs";
import path from "node:path";
import { hostImport } from "./host.js";
import { readPackageJson } from "./analyzer/files.js";
import { DEFAULT_POLICY, verdictFor } from "./analyzer/score.js";

/**
 * This plugin's own package root (realpath), so the gate never reviews
 * itself. import.meta.url resolves through pnpm symlinks into the store,
 * hence the realpath.
 */
export const OWN_ROOT = (() => {
  try {
    return realpathSync(fileURLToPath(new URL("..", import.meta.url)));
  } catch {
    return fileURLToPath(new URL("..", import.meta.url));
  }
})();

/**
 * Shared mutable state between the gate (import patch, entry-init hold)
 * and the host plugin service. Populated by the service at apply time;
 * the gate stays inert until then.
 */
export const gateState = {
  store: null,
  policy: () => ({ ...DEFAULT_POLICY }),
  profileDir: null,
  dshInstallRoot: null,
  log: (level, message) => {
    if (level === "error") console.error("[security-review]", message);
  },
  // package real dir -> { verdict, summary, reportPath } for blocked packages
  blocked: new Map(),
  // package real dir -> last decision { verdict, report } (warn/pass too)
  decisions: new Map()
};

/**
 * Resolve a module specifier the way the loader would, against a tree's
 * baseUrl (a file:// URL pointing at the include config directory).
 * Returns an absolute file path or null.
 */
export function resolveModulePath(baseUrl, specifier) {
  if (specifier.startsWith("cordis:")) return null;
  try {
    let parent;
    if (typeof baseUrl === "string" && /^file:/.test(baseUrl)) {
      parent = fileURLToPath(baseUrl);
    } else {
      parent = path.join(gateState.profileDir ?? process.cwd(), "__resolver__.js");
    }
    if (existsSync(parent) && statSync(parent).isDirectory()) parent = path.join(parent, "__resolver__.js");
    const req = createRequire(parent);
    if (specifier.startsWith(".")) {
      return req.resolve(specifier);
    }
    return req.resolve(specifier, { paths: [path.dirname(parent)] });
  } catch {
    return null;
  }
}

/**
 * Walk up from a resolved module path to the nearest package.json and
 * return the package directory (realpath) or null.
 */
export function packageDirOf(resolvedPath) {
  let dir = path.dirname(resolvedPath);
  for (let i = 0; i < 40; i++) {
    if (existsSync(path.join(dir, "package.json"))) {
      try { return realpathSync(dir); } catch { return dir; }
    }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
  return null;
}

/**
 * Decide whether a resolved module belongs to a reviewable out-of-tree
 * plugin. Returns null (skip), or { packageDir, name, own }.
 */
export function scopeOfResolved(resolvedPath, baseUrl) {
  const packageDir = packageDirOf(resolvedPath);
  if (!packageDir) return null;
  if (packageDir === OWN_ROOT || packageDir.startsWith(OWN_ROOT + path.sep)) return { packageDir, name: null, own: true };
  const pkg = readPackageJson(packageDir);
  if (!pkg) return null;
  const profileDir = gateState.profileDir ? realpathSyncSafe(gateState.profileDir) : null;
  const installRoot = gateState.dshInstallRoot ? realpathSyncSafe(gateState.dshInstallRoot) : null;
  const underProfile = profileDir && packageDir.startsWith(profileDir + path.sep);
  const underInstall = installRoot && packageDir.startsWith(installRoot + path.sep);
  const isDshPlugin = Boolean(pkg.dsh?.bundle || pkg.dsh?.client || pkg.dsh?.profile || pkg.dsh?.plugin);
  if (underInstall) return null;
  if (underProfile) return { packageDir, name: pkg.name ?? null };
  if (isDshPlugin) return { packageDir, name: pkg.name ?? null };
  return null;
}

function realpathSyncSafe(dir) {
  try { return realpathSync(dir); } catch { return dir; }
}

/**
 * Install the EntryTree import patch exactly once. Every loader-driven
 * plugin import (future entries, HMR reloads, dynamic mounts) then flows
 * through the gate BEFORE module evaluation.
 *
 * The loader package is imported lazily from the host dsh installation so
 * that (a) this plugin's module graph never fails to load when it is added
 * as a local folder (dev install), and (b) the patched EntryTree is the very
 * same class instance the running loader uses.
 */
export async function installImportGate() {
  if (gateState.__armed) return;
  gateState.__armed = true;
  let EntryTree;
  try {
    const loader = await hostImport("@deepseek-ai/cordis-plugin-loader");
    EntryTree = loader.EntryTree;
  } catch (error) {
    gateState.log("error", "无法加载宿主包 @deepseek-ai/cordis-plugin-loader，导入门禁未启用: " + (error?.message ?? String(error)));
    return;
  }
  const original = EntryTree.prototype.import;
  EntryTree.prototype.import = async function gatedImport(name, getOuterStack) {
    try {
      const blocked = await gateBeforeImport(this, name);
      if (blocked) {
        const error = new Error("security-review blocked plugin " + name + ": " + blocked.summary + " (报告: " + blocked.reportPath + ")");
        error.code = "SECURITY_REVIEW_BLOCKED";
        throw error;
      }
    } catch (error) {
      if (error?.code === "SECURITY_REVIEW_BLOCKED") throw error;
      gateState.log("error", "import gate failure for " + name + ": " + (error?.message ?? String(error)));
    }
    return original.call(this, name, getOuterStack);
  };
}

/**
 * Per-import gate decision. Returns a blocking descriptor or null.
 */
async function gateBeforeImport(tree, name) {
  if (!gateState.store || !gateState.profileDir) return null;
  const resolved = resolveModulePath(tree?.ctx?.baseUrl, name);
  if (!resolved) return null;
  const scope = scopeOfResolved(resolved, tree?.ctx?.baseUrl);
  if (!scope || scope.own || !scope.packageDir) return null;
  const policy = gateState.policy();
  if (policy.mode === "audit-only") return null;
  if ((policy.allowlist ?? []).includes(scope.name) || (policy.allowlist ?? []).includes("*")) return null;
  const cachedBlock = gateState.blocked.get(scope.packageDir);
  if (cachedBlock) return cachedBlock;
  const decision = await decideFor(scope);
  if (decision?.blocked) return decision;
  return null;
}

/**
 * Review (with cache) and fold the policy into a blocking decision.
 */
export async function decideFor(scope, opts = {}) {
  const { report } = await gateState.store.reviewPackage(scope.packageDir, { spec: scope.name, fresh: opts.fresh });
  const policy = gateState.policy();
  const decision = verdictFor(report, policy);
  const summary = "结论 " + decision.verdict + "（评分 " + report.score + "）：" + (decision.reasons.join("；") || "-");
  const blocked = decision.action === "block" && policy.autoDisable !== false;
  const entry = {
    verdict: decision.verdict,
    summary,
    reportPath: gateState.store.latestDir + "/" + safeName(scope.name) + ".md",
    blocked,
    report
  };
  gateState.decisions.set(scope.packageDir, entry);
  if (blocked) gateState.blocked.set(scope.packageDir, entry);
  return entry;
}

function safeName(name) {
  return String(name ?? "unknown").replace(/[^A-Za-z0-9._@+-]/g, "_").slice(0, 120);
}
