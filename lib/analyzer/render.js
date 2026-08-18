import { LABELS } from "./score.js";

function sv(label) { return LABELS.severity[label] ?? label; }
function cat(label) { return LABELS.category[label] ?? label; }
function vd(label) { return LABELS.verdict[label] ?? label; }

/**
 * Render a review report as GitHub-flavored Markdown (zh).
 */
export function renderReportMarkdown(report) {
  const t = report.target ?? {};
  const lines = [];
  const out = (s) => lines.push(s);
  out("# 插件安全审查报告");
  out("");
  out("| 项目 | 内容 |");
  out("| --- | --- |");
  out("| 目标 | " + (t.spec ?? t.name ?? "?") + " |");
  out("| 名称 | " + (t.name ?? "?") + " |");
  out("| 版本 | " + (t.version ?? "?") + " |");
  out("| 来源 | " + (t.source ?? "?") + " |");
  out("| 审查时间 | " + (report.analyzedAt ?? "") + " |");
  out("| 扫描文件 | " + report.filesScanned + " 个（跳过 " + report.filesSkipped + " 个） |");
  out("| 安全评分 | **" + report.score + " / 100** |");
  out("| 结论 | **" + vd(report.verdict) + "** |");
  out("");
  out("## 结论与建议");
  out("");
  out("**结论：** " + vd(report.verdict) + "。" + (report.reasons?.length ? " " + report.reasons.join("；") + "。" : ""));
  out("");
  out("**建议：** " + (report.recommendation?.text ?? "") + "");
  out("");
  out("**安装命令：**");
  out("```sh");
  out(report.recommendation?.suggestedCommand ?? ("dsh-safe-plugin add " + (t.name ?? t.spec ?? "<package>")));
  out("```");
  out("");
  out("## 发现明细（共 " + (report.findings?.length ?? 0) + " 项）");
  out("");
  out("| 级别 | 类别 | 文件:行 | 说明 |");
  out("| --- | --- | --- | --- |");
for (const f of report.findings ?? []) {
  const loc = f.file + (f.line ? ":" + f.line : "");
  const msg = (f.message ?? "").replace(/\|/g, "\\|").replace(/\n/g, " ");
  const rec = f.recommendation ? "。建议：" + f.recommendation.replace(/\|/g, "\\|") : "";
  out("| " + sv(f.severity) + " | " + cat(f.category) + " | " + loc + " | " + msg + rec + " |");
  if (f.code) {
    out("");
    out("> " + f.id + " - " + loc);
    out(">");
    out("> ```");
    out("> " + f.code);
    out("> ```");
    out("");
  }
}
if (!(report.findings?.length)) {
  out("| - | - | - | 未发现明显问题 |");
}
out("");
out("---");
out("由 dsh-plugin-security-review 生成（规则引擎 + 评分模型，静态分析，无法覆盖原生二进制与动态加载内容）。");
return lines.join("\n");
}
