/**
 * Deobfuscation and lexical-strip helpers for the analyzer.
 * Zero-dependency: decode common encoding payloads (base64 / hex /
 * fromCharCode / \xNN) and re-scan them; strip JS literals so string/
 * comment content does not count as code evidence.
 */

/**
 * Strip comments, strings, template literals and regex literals from JS
 * source, leaving "code-ish" text for pattern matching. Approximate by
 * design; good enough to stop string/comment false positives.
 */
export function stripJsLiterals(text) {
  let out = "";
  let i = 0;
  const n = text.length;
  const isRegexStart = (prev) => !prev || "([,=:!&|?{};+-*%^~\t\n ".includes(prev);
  while (i < n) {
    const c = text[i];
    const d = text[i + 1];
    if (c === "/" && d === "/") { while (i < n && text[i] !== "\n") i++; continue; }
    if (c === "/" && d === "*") { i += 2; while (i < n && !(text[i] === "*" && text[i + 1] === "/")) i++; i += 2; continue; }
    if (c === "'" || c === '"') { const q = c; i++; while (i < n) { if (text[i] === "\\") { i += 2; continue; } if (text[i] === q) { i++; break; } i++; } continue; }
    if (c === "`") {
      i++;
      while (i < n) {
        if (text[i] === "\\") { i += 2; continue; }
        if (text[i] === "$" && text[i + 1] === "{") { out += "$"; i += 2; continue; } // keep interpolation as code signal
        if (text[i] === "`") { i++; break; }
        i++;
      }
      continue;
    }
    if (c === "/") {
      const prev = out.trimEnd().slice(-1);
      if (isRegexStart(prev)) {
        i++;
        let inClass = false;
        while (i < n) {
          if (text[i] === "\\") { i += 2; continue; }
          if (text[i] === "[") inClass = true;
          else if (text[i] === "]") inClass = false;
          else if (text[i] === "/" && !inClass) { i++; break; }
          i++;
        }
        continue;
      }
    }
    out += c;
    i++;
  }
  return out;
}

/**
 * Best-effort base64 decode of a clean base64 string (may contain + / =).
 */
function decodeBase64(value) {
  try {
    const cleaned = value.replace(/\s+/g, "");
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(cleaned) || cleaned.length < 8) return null;
    const buf = Buffer.from(cleaned, "base64");
    if (buf.length === 0 || buf.length * 4 < cleaned.length * 3 - 8) return null; // not real base64
    const decoded = buf.toString("utf8");
    if (decoded.includes("\uFFFD")) return null;
    return decoded;
  } catch {
    return null;
  }
}

/**
 * Decode one hex string to utf8 (only if it looks like real hex text).
 */
function decodeHex(value) {
  try {
    const cleaned = value.replace(/\s+/g, "");
    if (!/^(?:[0-9a-fA-F]{2})+$/.test(cleaned)) return null;
    const bytes = [];
    for (let i = 0; i < cleaned.length; i += 2) bytes.push(parseInt(cleaned.slice(i, i + 2), 16));
    const decoded = Buffer.from(bytes).toString("utf8");
    if (decoded.includes("\uFFFD")) return null;
    return decoded;
  } catch {
    return null;
  }
}

/**
 * Extract and decode payloads from JS source. Returns an array of
 * { kind, decoded, index } — decoded strings that look like real text.
 */
export function decodePayloads(text) {
  const out = [];
  const pushDecoded = (kind, index, decoded) => {
    if (!decoded) return;
    const clipped = decoded.slice(0, 2000);
    if (/[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(clipped)) return;
    out.push({ kind, decoded: clipped, index });
  };
  // Buffer.from("...", "base64" | "hex")
  const bufferRe = /Buffer\.from\s*\(\s*["']([^"']{8,})["']\s*,\s*["'](base64|hex)["']\s*\)/g;
  let m;
  while ((m = bufferRe.exec(text)) !== null) {
    const value = m[1];
    pushDecoded(m[2], m.index, m[2] === "base64" ? decodeBase64(value) : decodeHex(value));
  }
  // atob("...")
  const atobRe = /\batob\s*\(\s*["']([A-Za-z0-9+/]{8,}={0,2})["']\s*\)/g;
  while ((m = atobRe.exec(text)) !== null) pushDecoded("atob", m.index, decodeBase64(m[1]));
  // String.fromCharCode(99,117,114,108,...)
  const fccRe = /String\.fromCharCode\s*\(([0-9,\s]{16,})\)/g;
  while ((m = fccRe.exec(text)) !== null) {
    const nums = m[1].split(",").map((x) => Number(x.trim()));
    if (nums.some((x) => !Number.isInteger(x) || x < 0 || x > 0x10ffff)) continue;
    const decoded = String.fromCharCode(...nums.slice(0, 800));
    pushDecoded("fromCharCode", m.index, decoded);
  }
  // long \xNN runs (>= 8 bytes)
  const hexRunRe = /(?:\\x[0-9a-fA-F]{2}){8,}/g;
  while ((m = hexRunRe.exec(text)) !== null) {
    const hex = m[0].replace(/\\x/g, "");
    pushDecoded("hex-escape", m.index, decodeHex(hex));
  }
  return out;
}

/**
 * Sub-rules re-run over decoded payload text. Returns the first matching
 * { severity, label } or null.
 */
const DECODED_RULES = [
  { re: /(?:sk-[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/, severity: "critical", label: "解码内容含硬编码密钥" },
  { re: /(?:curl|wget|iwr|Invoke-WebRequest)[^\n|;]{0,80}(?:\||;|&&)\s*(?:sh|bash|powershell|pwsh|cmd|python|node)\b/i, severity: "critical", label: "解码内容含下载后执行命令" },
  { re: /(?:bash\s+-i|nc\s+-e|\/dev\/tcp|\/bin\/sh|mkfifo)/, severity: "critical", label: "解码内容含反弹 shell 特征" },
  { re: /https?:\/\/[^\s"']{8,}/, severity: "high", label: "解码内容含网络地址" },
  { re: /(?:rm\s+-rf|chmod\s+777|poweroff|reboot|mkfs|dd\s+if=)/, severity: "high", label: "解码内容含破坏性命令" },
  { re: /(?:process\.env|DEEPSEEK_API_KEY|OPENAI_API_KEY|AWS_SECRET|GITHUB_TOKEN)/, severity: "high", label: "解码内容读取敏感环境变量" }
];

/**
 * Scan decoded payloads for dangerous content.
 * Returns findings: { severity, message, index }.
 */
export function scanDecodedPayloads(payloads) {
  const findings = [];
  for (const payload of payloads) {
    for (const rule of DECODED_RULES) {
      const m = rule.re.exec(payload.decoded);
      if (m) {
        findings.push({
          severity: rule.severity,
          message: rule.label + "（" + payload.kind + " 编码，解码后命中）",
          index: payload.index
        });
        break;
      }
    }
  }
  return findings;
}
