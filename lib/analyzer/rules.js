import { KNOWN_NAMES, KNOWN_UNSCOPED, nearMiss } from "./known.js";
import { lineOf, snippetOf, countMatches, clip } from "./util.js";

export const MAX_FINDINGS = 300;
export const MAX_PER_RULE_FILE = 6;

const JS_EXTS = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"]);
const SHELL_EXTS = new Set([".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"]);
const SENSITIVE_ENV = /(DEEPSEEK_API_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|GH_TOKEN|GH_PAT|NPM_TOKEN|NPM_AUTH_TOKEN|SLACK_TOKEN|DISCORD_TOKEN|TELEGRAM_BOT_TOKEN|WEBHOOK|PASSWORD|SECRET|TOKEN)\s*[=:]|process\.env/;
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
      for (const key of hookKeys) {
        const script = scripts[key];
        if (typeof script !== "string" || !script.trim()) continue;
        DOWNLOAD_EXEC.lastIndex = 0;
        const severe = DOWNLOAD_EXEC.test(script);
        ctx.add({
          id: "install-script",
          severity: severe ? "critical" : "high",
          category: "scripting",
          file: "package.json",
          code: clip(script),
          message: "安装生命周期脚本 " + key + " 会在安装时自动执行" + (severe ? "，且脚本包含下载后执行的特征" : ""),
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
      // 必须是真实的 child_process 导入（require/import），避免规则源码自匹配
      const importRe = /require\s*\(\s*['"]child_process['"]\s*\)|from\s*['"]node:child_process['"]|from\s*['"]child_process['"]/;
      if (!importRe.test(text)) return;
      const re = /(?:\.|\b)(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(/g;
      runRegexRule(this, ctx, file, text, re, (m) => {
        const windowText = text.slice(m.index, m.index + 200);
        const severe = /shell\s*:\s*(?:true|1)\b|`|\$\{|(?:^|[^\\w])(?:exec|spawn)(?:Sync)?\s*\(\s*(?:[a-zA-Z_$][\w$]*|["'][^"']*\$)/.test(windowText);
        return { severity: severe ? "critical" : "high", message: "调用 child_process." + m[1] + (severe ? "：参数动态拼接或 shell:true，存在命令注入风险" : "：执行外部命令") };
      });
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
        const dynamic = /\$\{|\+\s*(?:[a-zA-Z_$][\w$]*|process\.env|atob|fromCharCode)|['"`]\s*\+/.test(windowText);
        const obfuscated = /(atob|fromCharCode|String\.fromCharCode|\\)/.test(windowText);
        if (!dynamic && !obfuscated) return { severity: "low", message: "eval/new Function（参数为静态字符串）" };
        return { severity: "critical", message: "动态代码执行：" + m[0].trim() + (obfuscated ? "（叠加混淆特征）" : "（参数动态拼接）") };
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
      const evalDynamic = /(\beval\s*\(|new\s+Function)/.test(text);
      // fromCharCode 是合法内置 API（如 Buffer/字节处理），单独出现不视为混淆；
      // 仅在与 eval 组合时升级为严重
      if (/\batob\s*\(|\bunescape\s*\(/.test(text) || (evalDynamic && /String\.fromCharCode/.test(text))) {
        ctx.add(makeFinding(this, ctx, file, 0, text, { severity: evalDynamic ? "critical" : "medium", message: "混淆特征：atob/unescape" + (evalDynamic ? "（与 eval/Function 组合）" : "") }));
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
      if (/(document\.cookie|localStorage|sessionStorage)/.test(text) && fileUsesNetwork(text)) {
        const idx = text.search(/(document\.cookie|localStorage|sessionStorage)/);
        ctx.add(makeFinding(this, ctx, file, idx, text, { severity: "high", message: "浏览器端读取 cookie/存储并联网" }));
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
