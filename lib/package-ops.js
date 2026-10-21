/**
 * profile 依赖的安装 / 卸载。
 *
 * 两代运行时的包操作入口不同：
 *
 *   - **0.2.x（桌面客户端）**：内置 `pluginManager` 服务负责 pnpm 调用、profile
 *     写锁、组合包（bundle）选择与热应用；桌面端把 pnpm 变成
 *     `electron --expose-internals pnpm.mjs`，由启动器经 `profileContext.packageManager`
 *     注入。此时直接 `spawn("pnpm")` / `spawn("dsh")` 一定失败——PATH 上没有它们。
 *   - **0.1.x（web 版）**：没有该服务，退回原来的 `dsh plugin add` / `pnpm remove`,
 *     但调用方式同样优先使用 `profileContext.packageManager`（如果启动器给了）。
 *
 * 因此这里统一成 `{install(spec), remove(name), describe()}`，由调用方只关心结果。
 */

import { spawn } from "node:child_process";
import { dshCliInvocation, getService, packageManagerInvocation } from "./desktop.js";

/** pluginManager 的错误码 → 面向用户的中文说明。 */
const ERROR_TEXT = {
  "not-bundle": "该包没有声明组合包补丁（dsh.bundle.patch），0.2.x/桌面端无法把它作为插件启用；依赖已回滚",
  "already-installed": "该包已安装（开启 HMR 时需先卸载再安装新版本）",
  "invalid-spec": "包描述不合法（空值或以 - 开头）",
  "not-found": "注册表里找不到这个包",
  "not-a-package": "目标不是有效的 npm 包",
  network: "网络不可达（GitHub 或注册表）",
  "incompatible-version": "该插件的 DSH 版本要求不满足当前运行时",
  unknown: "插件管理器报告未知错误"
};

/** 把 pluginManager 的结果映射成 UI 需要的形状。 */
function mapManagerResult(result) {
  const application = result?.application;
  const ok = application !== "failed" && application !== "cancelled";
  const code = result?.error?.code;
  let message;
  if (!ok) message = "失败：" + (ERROR_TEXT[code] ?? code ?? "unknown");
  else if (application === "applied") message = "已应用（无需重启）";
  else if (application === "cancelled") message = "已取消";
  else message = "已保存，重启 dsh 后完全生效";
  return {
    ok,
    message,
    requiresRestart: application === "restart-required",
    application: application ?? null,
    errorCode: code ?? null,
    result: result ?? null
  };
}

/**
 * 用给定命令跑一个子进程并收集输出（不经过 shell，避免命令注入）。
 * @returns Promise<{ok, exitCode, message}>；启动失败也 resolve。
 */
function run(command, args, { cwd, env }) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(command, args, {
        cwd,
        env: { ...process.env, ...(env ?? {}) },
        shell: process.platform === "win32",
        windowsHide: true
      });
    } catch (error) {
      resolve({ ok: false, exitCode: -1, message: "启动失败: " + (error?.message ?? String(error)) });
      return;
    }
    let output = "";
    const collect = (chunk) => {
      output += chunk.toString();
      if (output.length > 4000) output = output.slice(-4000);
    };
    child.stdout?.on("data", collect);
    child.stderr?.on("data", collect);
    child.on("error", (error) => {
      resolve({ ok: false, exitCode: -1, message: (output || "") + "启动失败: " + (error?.message ?? String(error)) });
    });
    child.on("close", (code) => {
      resolve({ ok: code === 0, exitCode: code, message: output.trim().slice(-2000) });
    });
  });
}

/**
 * 创建 profile 包操作器。
 * @param options - ctx、profile 描述、运行时描述、日志函数。
 */
export function createPackageOps({ ctx, profile, runtime, log = () => {} }) {
  const pm = packageManagerInvocation(profile);
  const cli = runtime ? dshCliInvocation(runtime) : null;

  /**
   * pluginManager 必须**延迟**读取：它和本插件在同一批 entry 里启动，apply 时
   * 往往还没就绪（实测桌面端 apply 阶段 `ctx.get("pluginManager")` 返回 undefined）。
   * 调用时再取，就总能拿到已激活的服务。
   */
  const managerNow = () => getService(ctx, "pluginManager");
  const hasManager = () => typeof managerNow()?.installBundle === "function";

  /** 安装一个包；返回与 service 其他方法一致的形状。 */
  async function install(spec) {
    if (hasManager()) {
      try {
        const result = await managerNow().installBundle(spec, { activate: true });
        const mapped = mapManagerResult(result);
        log(mapped.ok ? "info" : "warn", "pluginManager 安装 " + spec + "：" + mapped.message);
        return { ...mapped, via: "plugin-manager" };
      } catch (error) {
        const message = "pluginManager 安装失败: " + (error?.message ?? String(error));
        log("warn", message);
        return { ok: false, message, requiresRestart: false, via: "plugin-manager" };
      }
    }
    if (cli && profile?.name) {
      const args = [...cli.args, "plugin", "--profile", profile.name, "add", spec, "--ignore-scripts"];
      const result = await run(cli.command, args, { cwd: profile.dir, env: cli.env });
      return { ...result, requiresRestart: result.ok, via: cli.source };
    }
    return { ok: false, message: "当前环境没有可用的安装通道（既无 pluginManager，也无 dsh CLI）", requiresRestart: false, via: "none" };
  }

  /** 卸载一个 profile 依赖；保留旧实现的名字校验。 */
  async function remove(name) {
    if (!/^(@[a-z0-9-_.]+\/)?[a-z0-9-_.]+$/i.test(String(name ?? ""))) {
      return { ok: false, message: "非法包名", requiresRestart: false, via: "none" };
    }
    const manager = managerNow();
    if (typeof manager?.removeBundle === "function") {
      try {
        const result = await manager.removeBundle(name);
        const mapped = mapManagerResult(result);
        log(mapped.ok ? "info" : "warn", "pluginManager 卸载 " + name + "：" + mapped.message);
        return { ...mapped, via: "plugin-manager" };
      } catch (error) {
        log("warn", "pluginManager 卸载失败，回退到包管理器: " + (error?.message ?? String(error)));
      }
    }
    const result = await run(pm.command, [...pm.args, "remove", name], { cwd: profile?.dir });
    return { ...result, requiresRestart: true, via: pm.source };
  }

  return {
    install,
    remove,
    describe() {
      return {
        via: hasManager() ? "plugin-manager" : cli ? cli.source : pm.source,
        canInstall: hasManager() || Boolean(cli),
        canRemove: true,
        profileDir: profile?.dir ?? null,
        packageManager: pm.source
      };
    }
  };
}
