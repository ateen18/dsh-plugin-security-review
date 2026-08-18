import path from "node:path";
import { fileURLToPath } from "node:url";
import { realpathSync } from "node:fs";
import { installImportGate, gateState, resolveModulePath, scopeOfResolved, decideFor } from "./gate.js";
import { findDshInstallRoot } from "./host.js";
import { ReviewStore } from "./store.js";
import { registerSettings, normalizePolicy } from "./settings.js";
import { registerTools } from "./tools.js";
import { ManagedPatch } from "./patch-manager.js";
import { reviewSpec, renderReportMarkdown } from "./analyzer/index.js";

export const name = "security-review";
export const inject = [];

/**
 * dsh-plugin-security-review host half.
 *
 * Runtime layers (see docs/design.md for the threat model):
 *  1. import gate — every loader-driven plugin import after our apply is
 *     reviewed before module evaluation; blocked entries fail the import
 *     with a SECURITY_REVIEW_BLOCKED error before any plugin code runs.
 *  2. boot audit — after the loader settles, every composed plugin row is
 *     reviewed (verdict-cached) and blocked rows are disabled via
 *     loader.update plus a managed `disabled: true` block written into the
 *     profile's cordis.patch.yml, so the NEXT boot skips their import
 *     entirely (fail-closed across reboots).
 *  3. install gate — the companion CLI `dsh-safe-plugin add` performs the
 *     deterministic pre-install review before pnpm ever runs.
 */
export async function apply(ctx, config = {}) {
  let disposed = false;
  const log = (level, message) => {
    try {
      const logger = ctx.logger ? ctx.logger("security-review") : null;
      if (logger?.[level]) logger[level](message);
      else console.error("[security-review]", message);
    } catch {
      console.error("[security-review]", message);
    }
  };

  // ---- resolve the profile directory from the include baseUrl ----
  let profileDir = null;
  try {
    const base = ctx.baseUrl;
    if (typeof base === "string" && /^file:/.test(base)) {
      profileDir = realpathSync(fileURLToPath(base));
    }
  } catch {}

  // ---- resolve the dsh installation root (in-box packages are exempt) ----
  const dshInstallRoot = findDshInstallRoot();

  const store = new ReviewStore();
  const managedPatch = profileDir ? new ManagedPatch(profileDir) : null;

  let policy = normalizePolicy(config);
  const policyNow = () => policy;

  gateState.store = store;
  gateState.profileDir = profileDir;
  gateState.dshInstallRoot = dshInstallRoot;
  gateState.policy = policyNow;
  gateState.log = log;
  try {
    await installImportGate();
  } catch (error) {
    log("error", "导入门禁安装失败: " + String(error?.message ?? error));
  }

  let lastRows = [];
  let auditRunning = null;
  let auditTimer = null;

  const audit = async (opts = {}) => {
    if (disposed) return { rows: [], summary: "" };
    if (auditRunning) return auditRunning;
    auditRunning = (async () => {
      const loader = ctx.get("loader");
      if (!loader) return { rows: [], summary: "" };
      try { await loader.await(); } catch {}
      if (disposed || ctx.get("loader") === undefined) return { rows: [], summary: "" };
      const rows = [];
      let entries = [];
      try { entries = [...loader.entries()]; } catch { entries = []; }
      for (const entry of entries) {
        const entryName = entry.options?.name;
        if (!entryName || entryName.startsWith("cordis:") || entry.options?.group) continue;
        const resolved = resolveModulePath(ctx.baseUrl, entryName);
        if (!resolved) continue;
        const scope = scopeOfResolved(resolved, ctx.baseUrl);
        if (!scope || scope.own || !scope.packageDir) continue;
        let decision;
        try {
          decision = await decideFor(scope, { fresh: opts.fresh });
        } catch (error) {
          log("error", "audit decision failed for " + entryName + ": " + String(error?.message ?? error));
          continue;
        }
        const blocked = decision.blocked && policyNow().autoDisable !== false;
        rows.push({
          id: entry.options.id ?? entry.id,
          name: entryName,
          packageDir: scope.packageDir,
          verdict: decision.verdict,
          score: decision.report.score,
          findings: decision.report.findings.length,
          blocked,
          disabled: Boolean(entry.disabled),
          reportPath: decision.reportPath
        });
        if (blocked && !entry.disabled) {
          try {
            await loader.update(entry.id, { disabled: true });
            log("warn", "已拦截并禁用插件 " + entryName + "（" + decision.summary + "）");
            ctx.emit("security-review/blocked", { id: entry.options.id ?? entry.id, name: entryName, verdict: decision.verdict, report: decision.report });
          } catch (error) {
            log("error", "禁用插件 " + entryName + " 失败: " + String(error?.message ?? error));
          }
        }
        ctx.emit("security-review/report", decision.report);
      }
      const blockedIds = rows.filter((row) => row.blocked).map((row) => row.id);
      if (managedPatch && policyNow().autoPatchProfile) {
        try {
          const changed = managedPatch.sync(blockedIds);
          if (changed) log("info", "已同步 profile cordis.patch.yml 托管拦截块（" + blockedIds.length + " 行）");
        } catch (error) {
          log("error", "托管拦截块写入失败: " + String(error?.message ?? error));
        }
      }
      lastRows = rows;
      const summary = statusSummary(rows);
      log("info", summary);
      ctx.emit("security-review/complete", { rows, blocked: blockedIds, summary });
      return { rows, summary };
    })().finally(() => {
      auditRunning = null;
    });
    return auditRunning;
  };

  // ---- settings section (policy surface in the web settings UI) ----
  try {
    await registerSettings(ctx, config, (nextPolicy) => {
      policy = nextPolicy;
      gateState.policy = policyNow;
      log("info", "策略更新: " + JSON.stringify(policy));
      if (auditTimer) clearTimeout(auditTimer);
      auditTimer = setTimeout(() => { auditTimer = null; void audit(); }, 200);
    });
  } catch (error) {
    log("error", "设置区注册失败: " + String(error?.message ?? error));
  }

  // ---- agent tools ----
  const service = {
    async reviewTarget(target, opts = {}) {
      const { report } = await reviewSpec(target, { fresh: opts.fresh, policy: policyNow(), cwd: process.cwd() });
      await store.save(report);
      ctx.emit("security-review/report", report);
      return { report, markdown: renderReportMarkdown(report) };
    },
    async status(opts = {}) {
      const { rows, summary } = await audit({ fresh: opts.fresh });
      return { rows, summary };
    }
  };
  try {
    await registerTools(ctx, service);
  } catch (error) {
    log("error", "工具注册失败: " + String(error?.message ?? error));
  }

  // ---- boot audit: run once the loader settles ----
  auditTimer = setTimeout(() => { auditTimer = null; void audit(); }, 0);

  // ---- teardown ----
  ctx.on("dispose", () => {
    disposed = true;
    if (auditTimer) clearTimeout(auditTimer);
  });
}

function statusSummary(rows) {
  if (!rows.length) return "security-review: 当前 profile 没有可审查的外部插件";
  const blocked = rows.filter((row) => row.blocked);
  const warns = rows.filter((row) => row.verdict === "warn");
  const parts = ["security-review: 已审查 " + rows.length + " 个插件"];
  if (blocked.length) parts.push("拦截 " + blocked.length + " 个（" + blocked.map((row) => row.name).join(", ") + "）");
  if (warns.length) parts.push("警告 " + warns.length + " 个（" + warns.map((row) => row.name).join(", ") + "）");
  return parts.join("；") + "。报告目录: " + new ReviewStore().root;
}

// Function `name` is non-writable; assignment would throw in ESM strict mode.
Object.defineProperty(apply, "name", { value: name });
