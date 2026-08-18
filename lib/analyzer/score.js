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
  autoDisable: true,
  autoPatchProfile: true,
  allowlist: []
});

/** Compute a 0..100 score from findings (capped deductions). */
export function scoreFindings(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  let score = 100;
  score -= Math.min(2, counts.critical) * 55;
  if (counts.critical > 2) score -= (counts.critical - 2) * 10;
  score -= Math.min(5, counts.high) * 18;
  if (counts.high > 5) score -= (counts.high - 5) * 4;
  // medium 单条扣分较低且有上限，避免常规 fs/网络用法把分数打到 0
  score -= Math.min(6, counts.medium) * 4;
  if (counts.medium > 6) score -= Math.min(12, Math.round((counts.medium - 6) * 0.5));
  score -= Math.min(10, counts.low) * 1;
  return Math.max(0, Math.round(score));
}

/**
 * Decide the verdict for a report. Returns
 * { verdict, reasons, action, suggestedCommand }.
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
  } else if (!exempt && report.score < 30) {
    verdict = "block";
    action = "block";
    reasons.push("综合评分 " + report.score + " 低于阈值 30");
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
