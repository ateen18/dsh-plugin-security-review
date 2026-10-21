import path from "node:path";
import { createRequire } from "node:module";
import { realpathSync, existsSync, readFileSync } from "node:fs";
import { installImportGate, gateState, resolveModulePath, scopeOfResolved, decideFor, packageDirOf } from "./gate.js";
import { findDshInstallRoot, findDshRuntime } from "./host.js";
import { ReviewStore } from "./store.js";
import { registerSettings, normalizePolicy, policyToSettings } from "./settings.js";
import { registerTools } from "./tools.js";
import { ManagedPatch } from "./patch-manager.js";
import { startInstallWatcher } from "./watcher.js";
import { buildSecurityReviewApi } from "./api.js";
import { installRuntimeGuard } from "./runtime-guard.js";
import { createPackageOps } from "./package-ops.js";
import { describeRuntime, installGateSupport, isAsarPath, resolveProfileContext } from "./desktop.js";
import { readPackageJson } from "./analyzer/files.js";
import { reviewSpec, renderReportMarkdown } from "./analyzer/index.js";
import { summarizeRisks } from "./analyzer/score.js";

export const name = "security-review";
export const inject = [];

/**
 * dsh-plugin-security-review host half.
 *
 * Runtime layers (see docs/design.md for the threat model):
 *  1. install gate — patches dsh's bin.js so that `dsh plugin add` triggers
 *     a pre-install review (download → static analysis → verdict gate) before
 *     pnpm ever runs. **只能在 web（可写的 dsh 安装）上工作**；桌面客户端把
 *     运行时打包进 app.asar，install-gate 会显式报告不可用。
 *  2. import gate — every loader-driven plugin import after our apply is
 *     reviewed before module evaluation; blocked entries fail the import
 *     with a SECURITY_REVIEW_BLOCKED error before any plugin code runs.
 *  3. boot audit — after the loader settles, every composed plugin row is
 *     reviewed (verdict-cached) and blocked rows are disabled via
 *     loader.update plus a managed `disabled: true` block written into the
 *     profile's cordis.patch.yml, so the NEXT boot skips their import
 *     entirely (fail-closed across reboots).
 *  4. install watcher — monitors the profile's package.json for dependency
 *     changes; when an install bypasses the gates, new/changed packages are
 *     re-reviewed immediately post-install.
 *  5. companion CLI `dsh-safe-plugin add` — the deterministic pre-install
 *     review flow (same engine, more options like --json, --force).
 *
 * 桌面端差异（见 lib/desktop.js）：profile 位置来自 `profileContext`；安装/卸载走
 * 内建 `pluginManager` 或启动器注入的 packageManager；install-gate 不可用。
 */
export async function apply(ctx, config = {}) {
  // 顶层兜底：任何内部异常只记录日志，绝不让本插件的 entry 失败导致 dsh 启动失败
  try {
  let disposed = false;
  // cordis 4：未注入的服务不能通过 `ctx.logger` 读（会抛 cannot get property），
  // 而 logger 是可选服务，所以每次走 ctx.get 取；取不到就退回 console.error。
  const resolveLogger = () => {
    try {
      return typeof ctx.get === "function" ? ctx.get("logger") : null;
    } catch {
      return null;
    }
  };
  const log = (level, message) => {
    try {
      const service = resolveLogger();
      const logger = service ? service("security-review") : null;
      if (logger?.[level]) logger[level](message);
      else console.error("[security-review]", message);
    } catch {
      console.error("[security-review]", message);
    }
  };

  // ---- 运行环境：profile 位置、dsh 运行时、打包标记 ----
  const runtime = findDshRuntime();
  const profile = resolveProfileContext(ctx);
  const profileDir = profile.dir;

  // ---- 官方包免审判定根（打包运行时用运行时根，普通安装用 dsh 包目录）----
  const dshInstallRoot = findDshInstallRoot();

  const store = new ReviewStore();
  const managedPatch = profileDir ? new ManagedPatch(profileDir) : null;

  const packaged = Boolean(runtime?.packaged) || /\.asar([\\/]|$)/i.test(String(dshInstallRoot ?? ""));
  const gateSupport = installGateSupport({ dshDir: runtime?.dshDir, packaged });
  const packageOps = createPackageOps({ ctx, profile, runtime, log });

  let policy = normalizePolicy(config);
  const policyNow = () => policy;

  // ---- install-gate: 默认关闭（稳定性优先；桌面端不可用）----
  // 改写全局 dsh 的 lib/bin.js 属于高危操作：dsh 升级、目录只读、卸载残留、
  // 结构变化都可能让 dsh CLI 无法启动。默认不注入；若检测到历史残留注入
  // （旧版本曾自动注入），则自动移除，恢复全局 dsh 原状。
  // 安装期预审请使用独立的 dsh-safe-plugin CLI；如需 `dsh plugin add` 也走
  // 审查，可在设置中显式开启 installGate（文档已警告风险）。
  try {
    // 动态加载：install-gate 模块的缺陷绝不拖垮插件启动
    const { patchDshBin, unpatchDshBin, isPatched: isInstallGated } = await import("./install-gate.js");
    if (policy.installGate) {
      if (!gateSupport.supported) {
        log("warn", "install-gate 在当前运行时不可用（" + gateSupport.reason + "）：桌面客户端把 dsh 打包进 app.asar，不能改写其中的 lib/bin.js；安装预审请用设置里的“安全安装”或 dsh-safe-plugin CLI");
      } else {
        const result = patchDshBin(dshInstallRoot);
        if (result.written) {
          log("info", "install-gate 已注入 dsh bin.js（" + result.binPath + "）");
        } else if (result.patched) {
          log("info", "install-gate 已生效（bin.js 无需重写）");
        } else if (result.reason && result.reason !== "no dsh root") {
          log("warn", "install-gate 注入失败：" + result.reason);
        }
      }
    } else if (gateSupport.supported && dshInstallRoot && isInstallGated(dshInstallRoot)) {
      const removed = unpatchDshBin(dshInstallRoot);
      if (removed) {
        log("warn", "已移除全局 dsh bin.js 中的历史注入（install-gate 默认关闭，安装预审请用 dsh-safe-plugin CLI）");
      }
    }
  } catch (error) {
    log("warn", "install-gate 处理异常：" + String(error?.message ?? error));
  }

  gateState.store = store;
  gateState.profileDir = profileDir;
  gateState.dshInstallRoot = dshInstallRoot;
  gateState.policy = policyNow;
  gateState.log = log;

  // ---- 运行时工具调用守卫（默认 off；log 只记录，block 拦截危险调用）----
  let disposeRuntimeGuard = () => {};
  const syncRuntimeGuard = () => {
    try {
      disposeRuntimeGuard();
      disposeRuntimeGuard = installRuntimeGuard(ctx, { mode: policy.runtimeGuard, log });
    } catch (error) {
      log("error", "运行时守卫同步失败: " + String(error?.message ?? error));
    }
  };
  syncRuntimeGuard();

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
        let resolved = null;
        let scope = null;
        try {
          resolved = resolveModulePath(ctx.baseUrl, entryName, ctx.get("loader"));
          if (resolved) scope = scopeOfResolved(resolved, ctx.baseUrl);
        } catch (error) {
          log("warn", "解析插件路径失败（跳过） " + entryName + ": " + String(error?.message ?? error));
          continue;
        }
        if (!scope || scope.own || !scope.packageDir) continue;
        let decision;
        try {
          decision = await decideFor(scope, { fresh: opts.fresh });
        } catch (error) {
          log("error", "audit decision failed for " + entryName + ": " + String(error?.message ?? error));
          continue;
        }
        const blocked = decision.blocked && policyNow().autoDisable !== false;
        const pkg = readPackageJson(scope.packageDir);
        rows.push({
          id: entry.options.id ?? entry.id,
          name: entryName,
          version: pkg?.version ?? "?",
          packageDir: scope.packageDir,
          verdict: decision.verdict,
          risk: riskOf(decision.verdict),
          score: decision.report.score,
          findings: decision.report.findings.length,
          blocked,
          disabled: Boolean(entry.disabled),
          reportPath: decision.reportPath,
          summary: decision.summary,
          riskSummary: summarizeRisks(decision.report.findings, decision.verdict, decision.report.score)
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

  /**
   * 后台审计的统一入口：审计是 fire-and-forget 的，绝不能因为一次失败变成
   * unhandled rejection（dsh 会对未处理的 rejection fail-loud，等于让宿主退出）。
   */
  const safeAudit = (opts) => {
    try {
      void audit(opts).catch((error) => log("error", "审计失败: " + String(error?.message ?? error)));
    } catch (error) {
      log("error", "审计启动失败: " + String(error?.message ?? error));
    }
  };

  // ---- settings surface ----
  // 0.2.x（桌面）没有 installSettingsSection，策略由本插件自己的设置分区持久化；
  // 0.1.x（web）仍会额外挂到宿主设置页（registerSettings 里做特性检测）。
  let settingsController = null;
  try {
    settingsController = await registerSettings(ctx, config, (nextPolicy) => {
      policy = nextPolicy;
      gateState.policy = policyNow;
      syncRuntimeGuard();
      log("info", "策略更新: " + JSON.stringify(policy));
      if (auditTimer) clearTimeout(auditTimer);
      auditTimer = setTimeout(() => { auditTimer = null; safeAudit(); }, 200);
    });
    policy = settingsController.getPolicy();
    gateState.policy = policyNow;
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
    },
    async list() {
      if (!lastRows.length) await audit();
      const loader = ctx.get("loader");
      if (!loader) return { rows: [] };
      const rows = [];
      let entries = [];
      try { entries = [...loader.entries()]; } catch { entries = []; }
      const reviewedById = new Map(lastRows.map((row) => [row.id, row]));
      for (const entry of entries) {
        const entryName = entry.options?.name;
        if (!entryName || entryName.startsWith("cordis:") || entry.options?.group) continue;
        const id = entry.options.id ?? entry.id;
        const reviewed = reviewedById.get(id);
        const resolved = resolveModulePath(ctx.baseUrl, entryName, loader);
        const pkgDir = resolved ? packageDirOf(resolved) : null;
        // 打包运行时里官方包位于 app.asar 内：asar 路径是虚拟路径，realpath 会把它
        // 折回磁盘上的 app.asar 文件，前缀比较因此失效，这里直接用原路径比较。
        let installRootReal = null;
        try { if (dshInstallRoot) installRootReal = isAsarPath(dshInstallRoot) ? dshInstallRoot : realpathSync(dshInstallRoot); } catch {}
        const official = Boolean(pkgDir && installRootReal && pkgDir.startsWith(installRootReal + path.sep));
        rows.push({
          id,
          name: entryName,
          official,
          ...(reviewed ?? { reviewed: false, verdict: official ? "builtin" : "unknown", risk: official ? "safe" : "unknown", version: pkgDir ? (readPackageJson(pkgDir)?.version ?? "?") : "?", summary: official ? "dsh 内置插件，无需审查" : "尚未审查" }),
          ...(reviewed ? { reviewed: true } : {})
        });
      }
      return { rows };
    },
    async runReview() {
      const { rows, summary } = await audit({ fresh: true });
      return { rows, summary };
    },
    /**
     * 卸载一个 profile 依赖。桌面端走内置 pluginManager（带 profile 写锁与热应用），
     * web 端走 dsh CLI / pnpm。
     */
    async uninstall(name) {
      if (!profileDir) throw new Error("profile dir unavailable");
      if (!/^(@[a-z0-9-_.]+\/)?[a-z0-9-_.]+$/i.test(name)) throw new Error("invalid package name");
      const manifestFile = path.join(profileDir, "package.json");
      if (!existsSync(manifestFile)) throw new Error("profile manifest missing");
      const manifest = JSON.parse(readFileSync(manifestFile, "utf8"));
      const deps = manifest.dependencies ?? {};
      if (!(name in deps)) throw new Error("not a profile dependency: " + name);
      const result = await packageOps.remove(name);
      return {
        ...result,
        requiresRestart: result.requiresRestart === true,
        note: result.ok ? "已从依赖移除；重启 dsh 后完全生效" : (result.message ?? "卸载失败")
      };
    },
    /**
     * 审查 + 安装。安装通道与卸载一致：桌面端由 pluginManager 完成 pnpm 调用、
     * 组合包选择与热应用；web 端退回 dsh CLI。
     */
    async installTarget(target, opts = {}) {
      if (!profileDir) throw new Error("profile dir unavailable");
      const { report } = await reviewSpec(target, { policy: policyNow(), cwd: process.cwd() });
      const markdown = renderReportMarkdown(report);
      if (report.verdict === "block" && !opts.force) {
        return { ok: false, reason: "blocked", report, markdown, message: "审查结论为 block，已拒绝安装。可强制放行（风险自担）。" };
      }
      if (report.verdict === "warn" && !opts.force) {
        return { ok: false, reason: "needs-confirm", report, markdown, message: "存在中高危发现，需确认后安装。" };
      }
      const installSpec = await import("./analyzer/registry.js").then((m) => m.normalizeGitSpecForPnpm(target));
      const result = await packageOps.install(installSpec);
      await store.save(report);
      safeAudit({ fresh: true });
      return {
        ...result,
        reason: result.ok ? "installed" : "install-failed",
        report,
        markdown,
        requiresRestart: result.ok && result.requiresRestart !== false
      };
    },
    settings() {
      return {
        ok: true,
        settings: policyToSettings(settingsController?.getPolicy() ?? policy),
        file: settingsController ? undefined : null
      };
    },
    updateSettings(body) {
      if (!settingsController) throw new Error("设置控制器未就绪");
      const patch = body?.settings && typeof body.settings === "object" ? body.settings : body;
      settingsController.update(patch ?? {});
      return { ok: true, settings: policyToSettings(settingsController.getPolicy()) };
    },
    capabilities() {
      return {
        ok: true,
        ...describeRuntime({ ctx, dshDir: runtime?.dshDir, packaged, installGate: gateSupport }),
        packages: packageOps.describe()
      };
    },
    async gateStatus() {
      if (!gateSupport.supported) return { supported: false, enabled: false, reason: gateSupport.reason };
      const gate = await import("./install-gate.js");
      return { supported: true, enabled: gate.isPatched(dshInstallRoot), reason: null };
    },
    async gateSet(enable) {
      if (!gateSupport.supported) {
        return { ok: false, message: "当前运行时不可用 install-gate（" + gateSupport.reason + "）" };
      }
      const gate = await import("./install-gate.js");
      if (enable) {
        const result = gate.patchDshBin(dshInstallRoot);
        return { ok: result.patched, message: result.patched ? "已开启（install-gate 注入 dsh bin.js）" : ("开启失败：" + (result.reason ?? "未知")) };
      }
      const removed = gate.unpatchDshBin(dshInstallRoot);
      return { ok: removed, message: removed ? "已关闭（已移除注入）" : "已关闭（原本未注入）" };
    }
  };
  try {
    await registerTools(ctx, service);
  } catch (error) {
    log("error", "工具注册失败: " + String(error?.message ?? error));
  }

  // ---- settings web API（web 与桌面都注册；loopback-only）----
  // webServer 由并发批次中的 web-app entry 提供，本插件 apply 时可能尚未就绪，
  // 因此改为后台等待注册，不阻塞 apply。
  void (async () => {
    try {
      const webServer = await waitForService(ctx, "webServer", 8000);
      if (!webServer) {
        log("warn", "webServer 未在 8 秒内就绪，/api/security-review/* 未注册（headless/无 web 的 profile 属正常）");
        return;
      }
      const routes = buildSecurityReviewApi(service);
      // 逐条注册：一条路由失败（例如与宿主/其他插件重名）不应让其余路由一起消失。
      const disposers = [];
      let failed = 0;
      for (const route of routes) {
        try {
          disposers.push(webServer.register(route));
        } catch (error) {
          failed += 1;
          log("error", "路由注册失败 " + route.path + ": " + String(error?.message ?? error));
        }
      }
      ctx.on("dispose", () => { for (const dispose of disposers) dispose(); });
      log(failed ? "warn" : "info", "已注册 /api/security-review/*（" + disposers.length + "/" + routes.length + " 条路由，" + (packaged ? "桌面打包运行时" : "常规安装") + "）");
    } catch (error) {
      log("error", "设置 API 注册失败: " + String(error?.message ?? error));
    }
  })();

  // ---- boot audit: run once the loader settles ----
  auditTimer = setTimeout(() => { auditTimer = null; safeAudit(); }, 0);

  // ---- install watcher: fallback for paths that bypass the install gate ----
  let installWatcher = null;
  if (profileDir) {
    installWatcher = startInstallWatcher({
      profileDir,
      onChanged: async ({ added, changed }) => {
        const targets = [...new Set([...added, ...changed])];
        if (!targets.length) return;
        log("info", "检测到 profile 依赖变更，即时复审：" + targets.join(", "));
        for (const name of targets) {
          try {
            const req = createRequire(path.join(profileDir, "package.json"));
            const resolved = realpathSync(path.dirname(req.resolve(name + "/package.json")));
            const scope = { packageDir: resolved, name };
            const decision = await decideFor(scope, { fresh: true });
            ctx.emit("security-review/report", decision.report);
            const level = decision.verdict === "block" ? "error" : decision.verdict === "warn" ? "warn" : "info";
            log(level, "即时复审 " + name + "：" + decision.summary + "（报告: " + decision.reportPath + "）");
            if (decision.blocked) {
              ctx.emit("security-review/blocked", { name, verdict: decision.verdict, report: decision.report });
            }
          } catch (error) {
            log("error", "即时复审 " + name + " 失败：" + String(error?.message ?? error));
          }
        }
        // 同步 loader 已加载 entries 与 managed patch（block 的写入 disabled）
        safeAudit({ fresh: true });
      }
    });
  }

  log("info", "security-review 已就绪：" + (packaged ? "桌面客户端（打包运行时）" : "常规运行时") +
    "，profile=" + (profile.name ?? "?") + "，包操作=" + packageOps.describe().via +
    "，install-gate=" + (gateSupport.supported ? "可用" : "不可用/" + gateSupport.reason));

  // ---- teardown ----
  ctx.on("dispose", () => {
    disposed = true;
    if (auditTimer) clearTimeout(auditTimer);
    if (installWatcher) installWatcher.close();
    try { disposeRuntimeGuard(); } catch {}
  });
  } catch (error) {
    console.error("[security-review] apply 内部异常（已隔离，不影响 dsh 启动）:", error);
  }
}

function waitForService(ctx, name, timeoutMs) {
  return new Promise((resolve) => {
    const existing = ctx.get(name);
    if (existing) return resolve(existing);
    const started = Date.now();
    const timer = setInterval(() => {
      const svc = ctx.get(name);
      if (svc) { clearInterval(timer); resolve(svc); }
      else if (Date.now() - started > timeoutMs) { clearInterval(timer); resolve(null); }
    }, 100);
    ctx.on("dispose", () => { clearInterval(timer); resolve(null); });
  });
}

function riskOf(verdict) {
  if (verdict === "block") return "danger";
  if (verdict === "warn") return "warn";
  if (verdict === "pass" || verdict === "audit") return "safe";
  return "unknown";
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

