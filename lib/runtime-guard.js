/**
 * Runtime tool-call guard (optional, off by default).
 *
 * Installs a synchronous `ctx.tools.guard` that inspects every tool call
 * BEFORE dispatch and: `log` mode records warnings only; `block` mode
 * denies dangerous calls (destructive commands, SSRF targets, sensitive
 * file paths, prompt-injection phrases). The guard is pure and never
 * throws; on any internal error the call passes through (fail-open).
 */

/** Serialize tool arguments for pattern matching without losing data. */
function argsText(name, args) {
  try {
    if (typeof args !== "object" || args === null) return String(args ?? "");
    const parts = [];
    const walk = (value, prefix) => {
      if (typeof value === "string") { parts.push(prefix + value); return; }
      if (typeof value === "number" || typeof value === "boolean") return;
      if (Array.isArray(value)) { for (let i = 0; i < value.length; i++) walk(value[i], prefix); return; }
      if (typeof value === "object") { for (const key of Object.keys(value)) walk(value[key], prefix); }
    };
    walk(args, "");
    return parts.join("\n");
  } catch {
    return "";
  }
}

/**
 * Inspect one tool call. Returns { severity, reason } or null when clean.
 */
export function inspectToolCall(name, args) {
  const text = argsText(name, args);
  if (!text) return null;
  const find = (rules) => {
    for (const rule of rules) {
      rule.re.lastIndex = 0;
      if (rule.re.test(text)) return rule;
    }
    return null;
  };
  const danger = find(DANGER_RULES);
  if (danger) return { severity: "danger", reason: danger.reason };
  const warn = find(WARN_RULES);
  if (warn) return { severity: "warn", reason: warn.reason };
  return null;
}

const DANGER_RULES = [
  { re: /(?:rm\s+-rf?\s+[\/~]|rm\s+-rf?\s+\/|mkfs|dd\s+if=.*of=\/dev\/|:\s*\(\s*\)\s*\{\s*:\s*\|\s*:&\s*\};\s*:|bash\s+-i\s*>&\s*\/dev\/tcp|nc\s+-e\s*\/|>\/dev\/sda|chmod\s+777\s+\/|>\/etc\/(?:passwd|shadow|sudoers)|crontab\s+-[er]|iptables\s+-F|useradd\s|passwd\s+[a-z])/i, reason: "检测到破坏性/提权系统命令" },
  { re: /(?:curl|wget|iwr|Invoke-WebRequest)[^\n|;]{0,80}(?:\||;|&&)\s*(?:sh|bash|powershell|pwsh|cmd|python|node)\b/i, reason: "检测到下载后执行（curl|wget 管道给 shell）" },
  { re: /(?:169\.254\.169\.254|metadata\.google\.internal|file:\/\/\/|gopher:\/\/|(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3})/i, reason: "检测到 SSRF 目标（云 metadata/内网地址/非 http 协议）" },
  { re: /(?:^|[\\/])(?:\.ssh|\.aws|\.env|\.gnupg|\.kube|credentials|\.credentials)[\\/]|(?:^|[\\/])etc[\\/]shadow|id_rsa|kubeconfig/i, reason: "检测到敏感凭据文件访问" }
];

const WARN_RULES = [
  { re: /ignore\s+previous\s+instructions|忽略之前的指令|忽略之前的所有指令|from\s+now\s+on\s+you\s+are|从现在起你(?:是|要)/i, reason: "检测到提示词注入特征" },
  { re: /(?:poweroff|reboot|shutdown\s+-[hr]|mkfs\.)/i, reason: "检测到系统级操作" }
];

/**
 * Install the runtime guard. mode: 'off' | 'log' | 'block'.
 * Returns the disposer.
 */
export function installRuntimeGuard(ctx, opts = {}) {
  const mode = opts.mode ?? "off";
  const log = opts.log ?? (() => {});
  if (mode === "off" || !ctx.tools?.guard) return () => {};
  const guard = (execution) => {
    try {
      const hit = inspectToolCall(execution?.name, execution?.arguments);
      if (!hit) return undefined;
      const detail = "[security-review] 运行时守卫：" + hit.reason + "（工具 " + (execution?.name ?? "?") + "，级别 " + hit.severity + "）";
      if (mode === "block" && hit.severity === "danger") return "[security-review] 已拦截危险操作：" + hit.reason;
      log("warn", detail);
      return undefined;
    } catch {
      return undefined;
    }
  };
  try {
    return ctx.tools.guard(guard);
  } catch (error) {
    log("error", "运行时守卫安装失败: " + String(error?.message ?? error));
    return () => {};
  }
}
