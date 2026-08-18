import { hostImport } from "./host.js";
import { renderReportMarkdown } from "./analyzer/index.js";

/**
 * Register the model-facing review tools on a context that has `tools`.
 * Both tools are read-only: they analyze and report, never install.
 * `defineTool` is imported lazily from the running dsh installation so the
 * module graph loads even when the plugin is added as a local folder.
 */
export async function registerTools(ctx, service) {
  if (!ctx.tools) return;
  const { defineTool } = await hostImport("@deepseek-ai/dsh-tools");
  ctx.tools.register(defineTool({
    name: "security_review",
    description: "对任意 DSH 插件/ npm 包做静态安全审查（不执行其代码）：支持本地目录、npm 包名@版本、tarball URL。返回安全评分、逐条发现、结论与安装建议。安装插件前应先调用本工具预审。",
    parameters: {
      target: { type: "string", required: true, description: "审查目标：本地目录路径（含 package.json）、npm 包名（可带 @版本，如 dsh-plugin-foo@1.2.3）、git URL 或 .tgz 下载地址" },
      profile: { type: "string", description: "已安装插件按此 dsh profile 上下文审查（缺省 web）；对本地目录/远程包无影响" },
      fresh: { type: "boolean", description: "true 时跳过缓存重新分析（默认 false）" }
    },
    output: {
      schema: {
        type: "object",
        additionalProperties: false,
        properties: {
          report: { type: "json", required: true },
          markdown: { type: "string" }
        }
      },
      render: (_args, value) => [{ type: "text", text: value.markdown ?? "（报告为空）" }]
    },
    timeoutMs: 180000,
    isConcurrencySafe: () => true,
    async execute(args) {
      const target = String(args.target ?? "").trim();
      if (!target) throw new Error("target 不能为空");
      const { report, markdown } = await service.reviewTarget(target, { fresh: Boolean(args.fresh), profile: args.profile });
      return { report, markdown };
    }
  }));

  ctx.tools.register(defineTool({
    name: "security_review_status",
    description: "列出当前 dsh profile 中已安装插件的安全审查状态（结论/评分/发现数/是否被拦截禁用），并给出最新审查报告路径。",
    parameters: {
      profile: { type: "string", description: "审查的 dsh profile（缺省当前运行的 profile）" },
      fresh: { type: "boolean", description: "true 时对已安装插件重新分析（默认 false，用缓存）" }
    },
    output: {
      schema: {
        type: "object",
        additionalProperties: false,
        properties: {
          rows: { type: "array", required: true, items: { type: "json" } },
          summary: { type: "string", required: true }
        }
      },
      render: (_args, value) => [{ type: "text", text: value.summary }]
    },
    timeoutMs: 120000,
    isConcurrencySafe: () => true,
    async execute(args) {
      return service.status({ fresh: Boolean(args.fresh), profile: args.profile });
    }
  }));
}

export { renderReportMarkdown };
