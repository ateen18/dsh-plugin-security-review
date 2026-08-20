/**
 * Scoring, verdict, and policy application for review reports.
 */

export const SEVERITY_WEIGHT = {
  critical: 60,
  high: 25,
  medium: 10,
  low: 3,
  info: 1
};

export const DEFAULT_POLICY = Object.freeze({
  mode: "standard",       // standard | strict | audit-only
  // 稳定性优先：审计默认只报告，不自动禁用/卸载插件、不写 profile patch
  // （防止误伤合法插件或在运行中卸载其服务导致 dsh 崩溃/下次启动缺服务）
  autoDisable: false,
  autoPatchProfile: false,
  installGate: false,     // 默认不改写全局 dsh bin.js（安装期拦截走 dsh-safe-plugin CLI）
  allowlist: []
});

/** Compute a 0..100 score from findings (capped deductions). */
export function scoreFindings(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  // 同一规则在不同文件/行重复触发不应线性叠加扣分：spawn 包装函数的 16 个
  // 调用点不比 1 个调用点危险 16 倍。按规则 ID 去重后再计分，重复出现只取
  // 该规则内最高严重级别一次，另加少量「蔓延」惩罚。
  const byRule = new Map();
  for (const f of findings) {
    const prev = byRule.get(f.id);
    const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    if (!prev || rank[f.severity] > rank[prev.severity]) byRule.set(f.id, { severity: f.severity, count: (prev?.count ?? 0) + 1 });
    else byRule.get(f.id).count += 1;
  }
  let score = 100;
  for (const rule of byRule.values()) {
    const spread = Math.min(2, Math.floor((rule.count - 1) / 5)); // 同规则多处出现的小额惩罚
    if (rule.severity === "critical") score -= 55 + spread * 5;
    else if (rule.severity === "high") score -= 18 + spread * 4;
    else if (rule.severity === "medium") score -= 4 + spread * 1;
    else if (rule.severity === "low") score -= 1;
  }
  return Math.max(0, Math.round(score));
}

/**
 * Decide the verdict for a report. Returns
 * { verdict, reasons, action, suggestedCommand }.
 *
 * block 只由「具体的高危信号」触发（critical 发现、strict 模式下的 high），
 * 不由累计低分触发：旧逻辑 score<30→block 会把功能性使用 child_process/
 * 网络的合法插件（SSH、进程管理、web UI）累计扣分后误杀。低分只降为 warn。
 */
export function verdictFor(report, policy = {}) {
  const p = { ...DEFAULT_POLICY, ...policy };
  const findings = report.findings ?? [];
  const criticals = findings.filter((f) => f.severity === "critical");
  const highs = findings.filter((f) => f.severity === "high");
  const allowed = new Set(p.allowlist ?? []);
  const exempt = allowed.has(report.target.name) || allowed.has("*");
  const reasons = [];
  let verdict = "pass";
  let action = "install";
  if (p.mode === "audit-only") {
    verdict = "audit";
    action = "audit";
    reasons.push("审查模式为 audit-only：只记录报告，不拦截安装或加载");
  } else if (!exempt && criticals.length > 0) {
    verdict = "block";
    action = "block";
    reasons.push(criticals.length + " 个 critical 级别发现（" + [...new Set(criticals.map((f) => f.id))].join("、") + "）");
  } else if (!exempt && (p.mode === "strict" && highs.length > 0)) {
    verdict = "block";
    action = "block";
    reasons.push("strict 模式：存在 " + highs.length + " 个 high 级别发现（" + [...new Set(highs.map((f) => f.id))].join("、") + "）");
  } else if (highs.length > 0) {
    verdict = "warn";
    action = "caution";
    reasons.push(highs.length + " 个 high 级别发现（" + [...new Set(highs.map((f) => f.id))].join("、") + "）");
  } else if (report.score < 60) {
    verdict = "warn";
    action = "caution";
    reasons.push("综合评分 " + report.score + " 低于阈值 60");
  }
  if (exempt) reasons.push("该包在 allowlist 中，豁免拦截");
  const command = report.target.name ? "dsh-safe-plugin add " + report.target.name : undefined;
  return { verdict, action, reasons, suggestedCommand: command };
}

/**
 * Human-readable severity/category/verdict labels (zh).
 */
export const LABELS = {
  severity: { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示" },
  category: {
    "dangerous-code": "危险代码",
    "data-exfiltration": "数据外传",
    network: "网络行为",
    "supply-chain": "供应链",
    obfuscation: "混淆/隐藏",
    "file-access": "文件访问",
    scripting: "安装脚本",
    hygiene: "包健康度"
  },
  verdict: { pass: "通过", warn: "警告", block: "拦截", audit: "仅审计" },
  action: { install: "可以安装", caution: "谨慎安装", block: "不建议安装", audit: "仅记录报告" }
};
