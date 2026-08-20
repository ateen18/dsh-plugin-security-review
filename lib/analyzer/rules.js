import { KNOWN_NAMES, KNOWN_UNSCOPED, nearMiss } from "./known.js";
import { lineOf, snippetOf, countMatches, clip } from "./util.js";

export const MAX_FINDINGS = 300;
export const MAX_PER_RULE_FILE = 6;

/**
 * 规则引擎版本号——变更规则逻辑时递增此值，使 verdict 缓存自动失效，
 * 防止修复后的规则仍复用旧缓存中的 block 判定。
 */
export const RULES_VERSION = 2;

const JS_EXTS = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"]);
const SHELL_EXTS = new Set([".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"]);
// 仅匹配「具名敏感凭据」的读取（API key / token / webhook 赋值或 process.env.XXX 形式）。
// 不再包含裸 process.env —— 读取任意环境变量（如 USER、PATH）与联网共存是
// SSH/网络类插件的正常形态，按旧逻辑会被误判为 critical 数据外传。
const SENSITIVE_ENV = /(DEEPSEEK_API_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|GH_PAT|NPM_TOKEN|NPM_AUTH_TOKEN|SLACK_TOKEN|DISCORD_TOKEN|TELEGRAM_BOT_TOKEN|WEBHOOK_URL?|PASSWORD|SECRET|TOKEN)\s*[=:]|process\.env\.(?:DEEPSEEK_API_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|GH_PAT|NPM_TOKEN|NPM_AUTH_TOKEN|SLACK_TOKEN|DISCORD_TOKEN|TELEGRAM_BOT_TOKEN)|process\.env\[[^\]]*(?:KEY|TOKEN|SECRET|PASSWORD)[^\]]*\]/;
const NETWORK_USE = /(fetch\s*\(|\.post\s*\(|\.put\s*\(|https?\.(request|get|post)\s*\(|XMLHttpRequest|WebSocket\s*\(|new\s+WebSocket|net\.connect|dgram\.createSocket|navigator\.sendBeacon)/;
const DOWNLOAD_EXEC = /(curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|certutil)[^\n|;]{0,200}(\||;|&&|\n)\s*(sh|bash|zsh|dash|cmd|powershell|pwsh|python|perl|ruby|node|npx|pnpm|npm|eval)\b/i;

/** Create one finding record (shared by every rule). */
function makeFinding(rule, ctx, file, index, text, extra = {}) {
  return {
    id: rule.id,
    severity: extra.severity ?? rule.severity,
    category: rule.category,
    file: file ? file.rel : "package.json",
    ...(index !== undefined ? { line: lineOf(text, index) } : {}),
    ...(index !== undefined ? { code: clip(snippetOf(text, index)) } : {}),
    message: extra.message ?? rule.message,
    ...(extra.recommendation ?? rule.recommendation ? { recommendation: extra.recommendation ?? rule.recommendation } : {})
  };
}

/**
 * Run one regex rule over one file with a per-file finding cap.
 */
function runRegexRule(rule, ctx, file, text, re, extraFor = () => ({})) {
  re.lastIndex = 0;
  let m;
  let n = 0;
  while ((m = re.exec(text)) !== null && n < MAX_PER_RULE_FILE) {
    ctx.add(makeFinding(rule, ctx, file, m.index, text, extraFor(m)));
    n += 1;
    if (m.index === re.lastIndex) re.lastIndex += 1;
  }
}

/** Whether one text file uses the network (whole-file check). */
function fileUsesNetwork(text) {
  NETWORK_USE.lastIndex = 0;
  return NETWORK_USE.test(text);
}

/** Whether one text file touches sensitive credentials. */
function fileTouchesSecrets(text) {
  SENSITIVE_ENV.lastIndex = 0;
  return SENSITIVE_ENV.test(text);
}

/**
 * The rule table. Each rule: id, severity, category, message, recommendation
 * and a check(ctx, file, text) that pushes findings through ctx.add.
 * Package-level rules receive file === null.
 */
export const RULES = [
  {
    id: "install-script",
    severity: "high",
    category: "scripting",
    message: "安装生命周期脚本：安装插件时 pnpm 会在你的 profile 目录里自动执行这段脚本",
    recommendation: "优先用 dsh-safe-plugin add 安装（会自动附加 --ignore-scripts），或逐行人工审查后再放行",
    check(ctx, file, text) {
      if (file) return;
      const scripts = ctx.packageJson?.scripts ?? {};
      const hookKeys = ["preinstall", "install", "postinstall", "prepare"];
      // 构建类命令（npm run build / tsc / esbuild 等）是 prepare 的常见合法用途，
      // 只有包含下载执行/网络/eval 等特征的安装脚本才保持 high/critical。
      const benignPrepare = /^(?:npm|pnpm|yarn|node)\s+(?:run\s+)?(?:build|test|lint|typecheck|prepare)(?:\s|$)|^(?:tsc|esbuild|vite\s+build|rollup)(?:\s|$)/;
      for (const key of hookKeys) {
        const script = scripts[key];
        if (typeof script !== "string" || !script.trim()) continue;
        DOWNLOAD_EXEC.lastIndex = 0;
        const severe = DOWNLOAD_EXEC.test(script);
        const benign = !severe && (key === "prepare" || key === "preinstall") && benignPrepare.test(script.trim());
        ctx.add({
          id: "install-script",
          severity: severe ? "critical" : benign ? "low" : "high",
          category: "scripting",
          file: "package.json",
          code: clip(script),
          message: "安装生命周期脚本 " + key + " 会在安装时自动执行" + (severe ? "，且脚本包含下载后执行的特征" : benign ? "（内容为常规构建命令，风险较低）" : ""),
          recommendation: "优先用 dsh-safe-plugin add 安装（自动附加 --ignore-scripts），或人工审查该脚本后再安装"
        });
      }
      for (const [key, script] of Object.entries(scripts)) {
        if (hookKeys.includes(key) || typeof script !== "string") continue;
        DOWNLOAD_EXEC.lastIndex = 0;
        if (DOWNLOAD_EXEC.test(script)) {
          ctx.add({
            id: "install-script",
            severity: "medium",
            category: "scripting",
            file: "package.json",
            code: clip(script),
            message: "脚本 " + key + " 包含下载后执行的特征（curl|wget|... 接 shell）",
            recommendation: "确认脚本内容来源可信"
          });
        }
      }
    }
  },
  {
    id: "download-exec",
    severity: "critical",
    category: "network",
    message: "下载后立即执行的模式（curl|wget|powershell ... 管道给 shell），典型的供应链投毒手法",
    recommendation: "删除该模式并改用完整性校验的固定依赖；确认执行内容来源可信",
    check(ctx, file, text) {
      if (!file) return;
      // 仅扫描 shell 脚本与 package.json 的 scripts；JS 中该模式由
      // danger-child-process 覆盖（避免规则引擎自身源码被误报）
      if (!(SHELL_EXTS.has(file.ext) || file.rel === "package.json")) return;
      runRegexRule(this, ctx, file, text, /(curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|certutil)[^\n|;]{0,200}(\||;|&&|\n)\s*(sh|bash|zsh|dash|cmd|powershell|pwsh|python|perl|ruby|node|npx|pnpm|npm|eval)\b/i);
    }
  },
  {
    id: "danger-child-process",
    severity: "high",
    category: "dangerous-code",
    message: "调用子进程执行命令。插件在宿主进程中运行，可以拿到 shell 与全部环境变量",
    recommendation: "确认为插件功能必需；拒绝不可信输入进入命令；避免 shell:true 与字符串拼接",
    check(ctx, file, text) {
      if (!file || !JS_EXTS.has(file.ext)) return;
      // 必须真实导入 child_process 才继续（避免规则引擎源码自匹配）。
      // 注意：本函数体内的注释刻意不写可被下方正则命中的示例代码。
      const importRe = /require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|from\s*['"](?:node:)?child_process['"]|require\s*\(\s*['"](?:node:)?child_process['"]\s*\)\s*\./;
      if (!importRe.test(text)) return;
      // 收集 child_process 在本文件的绑定名：整体导入别名 / 解构函数名 / 直接链式调用
      const aliases = new Set(["child_process"]);
      const wholeRe = /(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=\s*(?:await\s+)?require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|import\s+([a-zA-Z_$][\w$]*)\s*,?\s*(?:\{[^}]*\}\s*)?from\s*['"](?:node:)?child_process['"]/g;
      for (const m of text.matchAll(wholeRe)) {
        if (m[1]) aliases.add(m[1]);
        if (m[2]) aliases.add(m[2]);
      }
      const destructured = new Set();
      const destructureRe = /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*(?:await\s+)?require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|import\s*\{([^}]+)\}\s*from\s*['"](?:node:)?child_process['"]/g;
      for (const m of text.matchAll(destructureRe)) {
        const names = (m[1] ?? m[2] ?? "").split(",").map((s) => s.trim().split(/\s+as\s+/).pop().trim()).filter(Boolean);
        for (const name of names) destructured.add(name);
      }
      const METHOD_NAMES = ["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"];
      const methods = new Set(METHOD_NAMES);
      // severe 判定：只看调用点紧邻的参数区（前 120 字符），避免把附近
      // 错误消息的字符串拼接误认为命令注入；shell 选项区放宽到 240 字符。
      const judge = (methodName, matchIndex) => {
        const argWindow = text.slice(matchIndex, matchIndex + 120);
        const optWindow = text.slice(matchIndex, matchIndex + 240);
        const shellTrue = /shell\s*:\s*(?:true|1)\b/.test(optWindow);
        const shellFalse = /shell\s*:\s*(?:false|0)\b/.test(optWindow);
        // shell: <表达式>（非字面 false）在 Windows 上等价于开 shell
        const shellExpr = /shell\s*:\s*(?!false\b|0\b)[a-zA-Z_$]/.test(optWindow);
        const templateInterp = /`[^`]*\$\{/.test(argWindow);
        const isShellMethod = /^(?:exec|execSync)$/.test(methodName);
        const severe = shellTrue || (isShellMethod && templateInterp) || (templateInterp && !shellFalse) || (shellExpr && templateInterp);
        return severe;
      };
      // 1) 别名调用（整体导入后 alias.method 形态）
      for (const alias of aliases) {
        const re = new RegExp("(?:^|[^\\w$.])" + alias.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\s*\\.\\s*(" + METHOD_NAMES.join("|") + ")\\s*\\(", "g");
        runRegexRule(this, ctx, file, text, re, (m) => {
          const severe = judge(m[1], m.index);
          return { severity: severe ? "critical" : "high", message: "调用 child_process." + m[1] + (severe ? "：参数含模板插值或 shell 开启，存在命令注入风险" : "：执行外部命令") };
        });
      }
      // 2) 解构调用（import 的裸函数名）
      for (const name of destructured) {
        if (!methods.has(name)) continue;
        const re = new RegExp("(?:^|[^\\w$.])" + name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\s*\\(", "g");
        runRegexRule(this, ctx, file, text, re, (m) => {
          const severe = judge(name, m.index);
          return { severity: severe ? "critical" : "high", message: "调用 child_process." + name + (severe ? "：参数含模板插值或 shell 开启，存在命令注入风险" : "：执行外部命令") };
        });
      }
      // 3) 直接链式调用（require 后立即 .method）
      {
        const re = /require\s*\(\s*['"](?:node:)?child_process['"]\s*\)\s*\.\s*(" + METHOD_NAMES.join("|") + ")\s*\(/g;
        const re2 = new RegExp(re.source, "g");
        runRegexRule(this, ctx, file, text, re2, (m) => {
          const severe = judge(m[1], m.index);
          return { severity: severe ? "critical" : "high", message: "调用 child_process." + m[1] + (severe ? "：参数含模板插值或 shell 开启，存在命令注入风险" : "：执行外部命令") };
        });
      }
      // 不再对任意 .exec( 计数：RegExp.prototype.exec 与其他对象的 exec 方法
      // 与子进程无关。旧逻辑因此把大量合法插件判为 block 并写入禁用块，
      // 直接导致 dsh 启动失败（这是 2026-08-20 修复的启动崩溃根因）。
    }
  },
  {
    id: "dynamic-eval",
    severity: "critical",
    category: "obfuscation",
    message: "动态代码执行（eval / new Function / vm）。恶意插件用它隐藏并运行混淆后的载荷",
    recommendation: "在人工确认代码意图前不要安装；审查动态执行的内容来源",
    check(ctx, file, text) {
      if (!file || !JS_EXTS.has(file.ext)) return;
      const re = /\beval\s*\(|new\s+Function\s*\(|(?:^|[^\w.])Function\s*\(|vm\.(?:runInThisContext|runInNewContext|runInContext|compileFunction|Script)\s*\(/g;
      runRegexRule(this, ctx, file, text, re, (m) => {
        const windowText = text.slice(m.index, m.index + 160);
        const obfuscated = /(atob|fromCharCode|String\.fromCharCode|\\x[0-9a-fA-F]{2})/.test(windowText);
        const dynamic = /\$\{|\+\s*(?:[a-zA-Z_$][\w$]*|process\.env|atob|fromCharCode)|['"`]\s*\+/.test(windowText);
        if (obfuscated) {
          return { severity: "critical", message: "动态代码执行：" + m[0].trim() + "（叠加混淆特征）" };
        }
        if (!dynamic) return { severity: "low", message: "eval/new Function（参数为静态字符串）" };
        // "return " + 变量 是 schemastery/cordis 生态解析配置表达式的标准形态，
        // 输入来自用户自身配置；降为 high 而非 critical，避免整个生态被误判。
        const configParse = /new\s+Function\s*\(\s*["']return\s["']\s*\+/.test(windowText) || /new\s+Function\s*\(\s*["'][^"']*["']\s*\+\s*[a-zA-Z_$][\w$.]*/.test(windowText);
        const featureCheck = /new\s+Function\s*\(\s*["']["']\s*\)/.test(windowText);
        if (featureCheck) return { severity: "low", message: "new Function 空串特性检测" };
        if (configParse) return { severity: "high", message: "动态代码执行：" + m[0].trim() + "（拼接变量构造表达式，schemastery 配置解析形态）" };
        return { severity: "critical", message: "动态代码执行：" + m[0].trim() + "（参数动态拼接）" };
      });
    }
  },
  {
    id: "remote-code-load",
    severity: "critical",
    category: "network",
    message: "从远程地址动态加载并执行代码，绕过静态审查与依赖锁定",
    recommendation: "拒绝安装；若确需远程能力，改为显式白名单地址并人工审查",
    check(ctx, file, text) {
      if (!file || !JS_EXTS.has(file.ext)) return;
      runRegexRule(this, ctx, file, text, /import\s*\(\s*['"`]https?:/g);
      runRegexRule(this, ctx, file, text, /importScripts\s*\(\s*['"`]https?:/g, () => ({ severity: "high", message: "importScripts 加载远程脚本" }));
      const dyn = /(?:require\s*\(|import\s*\()\s*(?:[a-zA-Z_$][\w$]*)\s*\)/g;
      runRegexRule(this, ctx, file, text, dyn, () => ({ severity: "medium", message: "动态模块加载（参数为变量）", recommendation: "确认加载的模块清单是静态且可信的" }));
    }
  },
  {
    id: "data-exfil",
    severity: "critical",
    category: "data-exfiltration",
    message: "同一文件既读取敏感凭据/环境变量，又发起网络请求——存在外传凭据或会话数据的风险",
    recommendation: "拒绝安装，或确认网络出口与发送内容完全可信",
    check(ctx, file, text) {
      if (!file || !(JS_EXTS.has(file.ext) || SHELL_EXTS.has(file.ext))) return;
      const secrets = fileTouchesSecrets(text);
      const network = fileUsesNetwork(text);
      if (secrets && network) {
        const idx = text.search(SENSITIVE_ENV);
        ctx.add(makeFinding(this, ctx, file, idx >= 0 ? idx : 0, text));
      } else if (secrets) {
        const idx = text.search(SENSITIVE_ENV);
        ctx.add(makeFinding(this, ctx, file, idx >= 0 ? idx : 0, text, { severity: "medium", message: "读取敏感环境变量/凭据", recommendation: "确认为插件功能必需且不会离开本机" }));
      } else if (network && JS_EXTS.has(file.ext) && !ctx.packageJson?.dsh) {
        ctx.counters ??= {};
        const n = ctx.counters["data-exfil:low"] ?? 0;
        if (n < 3) {
          ctx.counters["data-exfil:low"] = n + 1;
          ctx.add(makeFinding(this, ctx, file, text.search(NETWORK_USE), text, { severity: "low", message: "存在网络活动", recommendation: "确认通信目标与发送内容" }));
        }
      }
    }
  },
  {
    id: "hardcoded-secret",
    severity: "critical",
    category: "data-exfiltration",
    message: "代码中包含硬编码凭据或 Webhook 地址（API key / token / 私钥 / Slack/Discord webhook）",
    recommendation: "立即轮换泄露的凭据并删除硬编码内容",
    check(ctx, file, text) {
      if (!file) return;
      runRegexRule(this, ctx, file, text, /sk-[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----/g);
      runRegexRule(this, ctx, file, text, /https?:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+/g, () => ({ severity: "critical", message: "硬编码 Slack webhook 地址" }));
      runRegexRule(this, ctx, file, text, /https?:\/\/(?:discord(?:app)?\.com|discord\.com)\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/g, () => ({ severity: "high", message: "硬编码 Discord webhook 地址" }));
    }
  },
  {
    id: "obfuscation",
    severity: "medium",
    category: "obfuscation",
    message: "混淆特征（fromCharCode/atob/unicode 转义/超长 base64 片段），恶意代码常用其隐藏载荷",
    recommendation: "要求作者提供源码并人工比对，或用反混淆工具还原后审查",
    check(ctx, file, text) {
      if (!file || !JS_EXTS.has(file.ext)) return;
      // atob 的结果必须真正流入 eval/Function 才构成 critical；
      // 打包产物（rollup/webpack 的浏览器 polyfill）中 atob 与 new Function
      // 共存是常态，按旧逻辑（共存即 critical）会把正常前端库全部判为 block。
      const evalFeed = /(?:eval|Function)\s*\([^)]*\b(?:atob|unescape)\b|(?:atob|unescape)\s*\([^)]*\)\s*(?:\+|,)?\s*(?:eval|new\s+Function)/.test(text);
      if (/\batob\s*\(|\bunescape\s*\(/.test(text)) {
        ctx.add(makeFinding(this, ctx, file, 0, text, {
          severity: evalFeed ? "critical" : "low",
          message: evalFeed ? "混淆特征：atob/unescape 结果直接进入 eval/Function 执行" : "使用 atob/unescape（Base64/URL 解码，常见于浏览器 polyfill，无 eval 组合时风险有限）"
        }));
      }
      if (evalFeed && /String\.fromCharCode/.test(text)) {
        ctx.add(makeFinding(this, ctx, file, 0, text, { severity: "critical", message: "混淆特征：fromCharCode 与 eval/Function 组合" }));
      }
      const hexEscapes = countMatches(/\\x[0-9a-fA-F]{2}/g, text);
      if (hexEscapes >= 20) {
        ctx.add(makeFinding(this, ctx, file, 0, text, { severity: "high", message: "大量十六进制转义序列（" + hexEscapes + " 处），疑似编码隐藏内容" }));
      }
      const b64 = /[A-Za-z0-9+/]{300,}={0,2}/.exec(text);
      if (b64) {
        const before = text.slice(Math.max(0, b64.index - 80), b64.index);
        if (!before.includes("sourceMappingURL")) {
          ctx.add(makeFinding(this, ctx, file, b64.index, text, { severity: "high", message: "超长 base64 片段，疑似嵌入二进制/加密载荷", recommendation: "解码该片段人工确认内容" }));
        }
      }
      const lines = text.split("\n");
      const veryLong = lines.some((line) => line.length > 2000);
      const avg = text.length / Math.max(1, lines.length);
      if ((veryLong || avg > 400) && lines.length > 50) {
        ctx.add(makeFinding(this, ctx, file, 0, text, { severity: "low", message: "疑似压缩/混淆代码且无源码", recommendation: "核对是否与源码仓库一致" }));
      }
    }
  },
  {
    id: "unsafe-fs",
    severity: "medium",
    category: "file-access",
    message: "文件系统操作。宿主插件不受沙箱限制，可以读写用户目录中的任意文件",
    recommendation: "确认路径不会拼接不可信输入、不会越出插件自身目录",
    check(ctx, file, text) {
      if (!file) return;
      if (JS_EXTS.has(file.ext)) {
        const re = /(writeFileSync|writeFile|appendFileSync|appendFile|unlinkSync|unlink|rmSync|renameSync|rename|chmodSync|chmod|truncateSync|truncate|mkdirSync|mkdtempSync)\s*\(/g;
        runRegexRule(this, ctx, file, text, re, (m) => {
          const windowText = text.slice(m.index, m.index + 160);
          const escape = /(\.dsh|\.credentials|sessions[/\\]|USERPROFILE|APPDATA|process\.env(?:\.|\[))/.test(windowText);
          return escape ? { severity: "high", message: "文件操作涉及用户目录/敏感路径（" + m[1] + "）" } : {};
        });
      }
      if (SHELL_EXTS.has(file.ext)) {
        runRegexRule(this, ctx, file, text, /\brm\s+-rf?\s+(?:\$|\w+[/\\])/g, () => ({ severity: "high", message: "危险删除命令 rm -rf（参数含变量/路径）" }));
        runRegexRule(this, ctx, file, text, /\bchmod\s+(?:777|a\+rwx)/g, () => ({ severity: "medium", message: "chmod 777 放宽权限" }));
      }
    }
  },
  {
    id: "native-binary",
    severity: "high",
    category: "dangerous-code",
    message: "包含原生二进制（.node/.exe/.dll 等），静态审查无法覆盖其行为",
    recommendation: "只有完全信任发布者时才安装；优先寻找纯 JS 实现",
    check(ctx, file, text) {
      if (file) return;
      for (const artifact of ctx.binary.slice(0, 5)) {
        ctx.add({ id: "native-binary", severity: "high", category: "dangerous-code", file: artifact.rel, code: artifact.bytes + " bytes", message: "原生二进制构件：" + artifact.rel, recommendation: "只有完全信任发布者时才安装；优先寻找纯 JS 实现" });
      }
      if (ctx.packageJson?.gypfile || ctx.filePaths.includes("binding.gyp")) {
        ctx.add({ id: "native-binary", severity: "medium", category: "dangerous-code", file: "package.json", message: "包含 node-gyp 原生构建（安装时会编译本地代码）", recommendation: "安装时审计构建脚本，或直接使用预编译产物" });
      }
      for (const rel of ctx.filePaths) {
        if (!JS_EXTS.has("." + rel.split(".").pop()?.toLowerCase())) continue;
        const textFile = ctx.textByRel.get(rel);
        if (!textFile) continue;
        if (/require\s*\(\s*['"](?:ffi-napi|ffi|koffi|bindings|ref-napi)['"]\s*\)/.test(textFile)) {
          ctx.add({ id: "native-binary", severity: "medium", category: "dangerous-code", file: rel, message: "加载原生模块（ffi/koffi/bindings）", recommendation: "确认为功能必需并信任该原生模块" });
          break;
        }
      }
    }
  },
  {
    id: "prototype-pollution",
    severity: "high",
    category: "dangerous-code",
    message: "原型污染特征（__proto__ / constructor.prototype 赋值）",
    recommendation: "确认对象键来源可信；使用 Object.create(null) 或键过滤",
    check(ctx, file, text) {
      if (!file || !JS_EXTS.has(file.ext)) return;
      runRegexRule(this, ctx, file, text, /__proto__\s*[.=:]|\[\s*['"]__proto__['"]\s*\]\s*[.=]|constructor\s*\[\s*['"]prototype['"]\s*\]\s*=/g);
    }
  },
  {
    id: "plain-http",
    severity: "medium",
    category: "network",
    message: "使用明文 HTTP 通信，内容可被中间人窃听/篡改",
    recommendation: "改用 HTTPS 并校验证书",
    check(ctx, file, text) {
      if (!file) return;
      runRegexRule(this, ctx, file, text, /['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[^'"`\s]+/g);
    }
  },
  {
    id: "dsh-host-abuse",
    severity: "high",
    category: "dangerous-code",
    message: "调用 loader 控制面：插件可卸载/禁用其他插件，篡改插件清单",
    recommendation: "确认为插件声明的核心功能（如插件管理器）后再放行",
    check(ctx, file, text) {
      if (!file || !JS_EXTS.has(file.ext)) return;
      runRegexRule(this, ctx, file, text, /ctx\.loader\.(?:update|remove|create|resolveGroup|resolve)\s*\(/g);
      runRegexRule(this, ctx, file, text, /(?:\$\(?:DSH_HOME|HOME|USERPROFILE|APPDATA)|~\/\.dsh|["'](?:[^"']*[\/\\]\.dsh[\/\\])/g, (m) => {
        const windowText = text.slice(Math.max(0, m.index - 60), m.index + 160);
        const verb = /readFileSync?|writeFileSync?|appendFileSync?|execSync?|spawnSync?|fetch\s*\(|https?\.(?:get|post|request)|require\s*\(|import\s*\(/.test(windowText);
        return verb
          ? { severity: "high", message: "引用 dsh 用户目录（~/.dsh）并伴随文件/网络操作，可能读取会话、凭据或设置", recommendation: "确认访问范围仅为插件自身数据" }
          : { severity: "low", message: "引用 dsh 用户目录（~/.dsh）", recommendation: "确认为插件功能必需" };
      });
      runRegexRule(this, ctx, file, text, /process\.exit\s*\(/g, () => ({ severity: "low", message: "process.exit 调用" }));
    }
  },
  {
    id: "miner-wallet",
    severity: "medium",
    category: "data-exfiltration",
    message: "硬编码加密货币地址，疑似挖矿/勒索载荷",
    recommendation: "确认为测试数据；生产代码中不应出现钱包地址",
    check(ctx, file, text) {
      if (!file) return;
      runRegexRule(this, ctx, file, text, /(?:bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}/g);
    }
  },
  {
    id: "client-browser-risk",
    severity: "medium",
    category: "dangerous-code",
    message: "浏览器端代码中的 DOM/存储操作，可能窃取页面内凭据或注入内容",
    recommendation: "审查渲染内容是否转义、是否读取其他插件的存储",
    check(ctx, file, text) {
      if (!file) return;
      const clientish = /(^|\/)client(\/|[-_.])/i.test(file.rel) || file.ext === ".jsx" || file.ext === ".tsx";
      if (!clientish) return;
      if (/innerHTML\s*=/.test(text)) {
        const idx = text.search(/innerHTML\s*=/);
        ctx.add(makeFinding(this, ctx, file, idx, text, { message: "innerHTML 直接赋值，存在 XSS 风险" }));
      }
      // localStorage + 联网在客户端是普遍形态（设置面板、皮肤、会话缓存都会如此），
      // 只有「读取的存储值流入网络请求参数」才升级为 high。
      if (/(document\.cookie|localStorage|sessionStorage)/.test(text) && fileUsesNetwork(text)) {
        const idx = text.search(/(document\.cookie|localStorage|sessionStorage)/);
        // 检查存储值是否直接拼进网络请求（fetch(url + value) / body: value 等）
        const flowsToNetwork = /(?:fetch|\.post|\.put|https?\.request)\s*\([^)]*(?:localStorage|sessionStorage|document\.cookie)|body\s*:\s*(?:localStorage|sessionStorage|document\.cookie)|localStorage\.getItem\([^)]*\)\s*(?:\+|\$\{|,\s*(?:body|url))/m.test(text);
        const readsCookie = /document\.cookie/.test(text);
        ctx.add(makeFinding(this, ctx, file, idx, text, {
          severity: flowsToNetwork || readsCookie ? "high" : "low",
          message: flowsToNetwork
            ? "浏览器端读取的存储值直接进入网络请求，存在数据外传通道"
            : readsCookie
              ? "浏览器端读取 document.cookie 并存在网络活动"
              : "浏览器端读写 localStorage/sessionStorage 并存在网络活动（常见于设置面板，确认读写的键仅限自身）"
        }));
      }
    }
  }
];

/** Package-level checks (manifest, supply chain). */
function packageChecks(ctx) {
  const pkg = ctx.packageJson ?? {};
  const add = (finding) => ctx.add({ file: "package.json", category: "supply-chain", ...finding });
  const name = ctx.meta?.name ?? pkg.name;
  const unscoped = name && name.includes("/") ? name.slice(name.indexOf("/") + 1) : name;
  if (unscoped) {
    for (const known of KNOWN_UNSCOPED) {
      if (KNOWN_NAMES.has(name)) break;
      const d = nearMiss(unscoped, known);
      if (d === 1) {
        add({
          id: "typosquat",
          severity: "high",
          message: "包名 " + name + " 与知名包 " + known + " 高度相似，可能是抢注/钓鱼包",
          recommendation: "核对作者、仓库与官网是否一致，确认不是同名仿冒包"
        });
        break;
      }
    }
  }
  const coreScoped = name && /^@(?:deepseek-ai|linxin666)\//.test(name) && !KNOWN_NAMES.has(name);
  if (coreScoped) {
    add({
      id: "typosquat",
      severity: "medium",
      message: "包名使用官方 dsh 插件命名空间但不在已知清单中",
      recommendation: "确认发布者与官方清单一致"
    });
  }
  if (!pkg.license && !pkg.licenses) {
    add({ id: "weak-metadata", severity: "medium", message: "缺少 license 声明", recommendation: "确认授权范围符合使用场景" });
  }
  if (!pkg.repository && !pkg.homepage && !pkg.bugs) {
    add({ id: "weak-metadata", severity: "medium", message: "缺少仓库/主页链接，无法核对源码", recommendation: "要求作者公开源码仓库" });
  }
  if (!pkg.author) {
    add({ id: "weak-metadata", severity: "low", message: "缺少作者信息" });
  }
  if (pkg.version === "0.0.0" || pkg.version === "0.0.1") {
    add({ id: "weak-metadata", severity: "medium", message: "版本号为 " + pkg.version + "，疑似占位/试探发布", recommendation: "观察仓库活跃度后再决定" });
  }
  const deps = { ...(pkg.dependencies ?? {}) };
  const depNames = Object.keys(deps);
  const suspicious = [];
  for (const dep of depNames) {
    const depUnscoped = dep.includes("/") ? dep.slice(dep.indexOf("/") + 1) : dep;
    if (!KNOWN_NAMES.has(dep)) {
      for (const known of KNOWN_UNSCOPED) {
        if (nearMiss(depUnscoped, known) === 1) { suspicious.push(dep + " (≈ " + known + ")"); break; }
      }
    }
    if (/^git[+:]|^github:|^https?:\/\//.test(String(deps[dep] ?? "")) && !suspicious.includes(dep)) {
      suspicious.push(dep + " (git/url 依赖)");
    }
  }
  for (const s of suspicious.slice(0, 3)) {
    add({ id: "suspicious-deps", severity: "high", message: "可疑依赖：" + s, recommendation: "核对依赖发布者与内容" });
  }
}

/**
 * Run all rules over a prepared analysis context.
 * ctx: { packageJson, meta, filePaths, textByRel, binary, add }
 * Returns the findings array (also mirrored into ctx.findings).
 */
export function runRules(ctx) {
  const findings = [];
  ctx.findings = findings;
  ctx.add = (finding) => {
    if (findings.length >= MAX_FINDINGS) return;
    findings.push({ ...finding, id: finding.id });
  };
  packageChecks(ctx);
  for (const rule of RULES) rule.check(ctx, null, "");
  for (const rule of RULES) {
    for (const file of ctx.files) {
      const text = ctx.textByRel.get(file.rel);
      if (text == null) continue;
      rule.check(ctx, file, text);
    }
  }
  return findings;
}
