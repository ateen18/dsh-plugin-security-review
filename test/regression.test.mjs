import path from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync, mkdtempSync } from "node:fs";
import os from "node:os";
import { test } from "node:test";
import assert from "node:assert/strict";
import { gunzipSync, gzipSync } from "node:zlib";
import { analyzePackageDir } from "../lib/analyzer/index.js";
import { runRules } from "../lib/analyzer/rules.js";
import { extractTgz } from "../lib/analyzer/tar.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dshHome = path.join(os.homedir(), ".dsh");
const profileNodeModules = path.join(dshHome, "profiles", "web", "node_modules");

function ustarHeader(name, size, type = "0", linkname = "") {
  const header = Buffer.alloc(512);
  const nameBuf = Buffer.alloc(100);
  const linkBuf = Buffer.alloc(100);
  nameBuf.write(name, 0, "utf8");
  linkBuf.write(linkname, 0, "utf8");
  header.write(nameBuf.toString("binary"), 0, 100, "binary");
  header.write("0000644", 100, 8, "utf8");
  header.write("0000000", 108, 8, "utf8");
  header.write("0000000", 116, 8, "utf8");
  header.write(size.toString(8).padStart(11, "0") + " ", 124, 12, "utf8");
  header.write("00000000000", 136, 12, "utf8");
  header.write("        ", 148, 8, "utf8");
  header.write(type, 156, 1, "utf8");
  header.write(linkBuf.toString("binary"), 157, 100, "binary");
  header.write("ustar ", 257, 6, "utf8");
  header.write("00", 263, 2, "utf8");
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += header[i];
  header.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, 8, "utf8");
  return header;
}

function makeTgz(entries) {
  const chunks = [];
  for (const entry of entries) {
    if (entry.type === "L") {
      const data = Buffer.from(entry.name, "utf8");
      chunks.push(ustarHeader("././@LongLink", data.length, "L"));
      chunks.push(data);
      chunks.push(Buffer.alloc((512 - (data.length % 512)) % 512));
      continue;
    }
    const data = Buffer.from(entry.content ?? "", "utf8");
    chunks.push(ustarHeader(entry.name, data.length, entry.type ?? "0", entry.linkname ?? ""));
    chunks.push(data);
    chunks.push(Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  chunks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(chunks));
}

function analyzeSnippets(files) {
  return runRules({
    packageJson: { name: "t" },
    meta: { name: "t", version: "1.0.0" },
    filePaths: Object.keys(files),
    textByRel: new Map(Object.entries(files)),
    files: Object.keys(files).map((rel) => ({ rel, ext: path.extname(rel) })),
    binary: [],
    counters: {}
  });
}

// ---- Regression: tar extraction (Buffer.toString offsets) ----
test("tar extraction handles ustar magic, longnames, symlinks, traversal", () => {
  const dest = mkdtempSync(path.join(os.tmpdir(), "dsh-fix-test-"));
  const longName = "packages/" + "a".repeat(110) + "/file.js";
  const tgz = makeTgz([
    { name: "package/package.json", content: "{}" },
    { type: "L", name: longName },
    { name: "short.js", content: "export const x = 1;" },
    { name: "../../escape.txt", content: "evil" },
    { name: "package/link", type: "2", linkname: "../outside" }
  ]);
  const result = extractTgz(tgz, dest);
  assert.ok(result.files.some((f) => f.endsWith("package.json")), "package.json extracted");
  assert.ok(result.files.some((f) => f.endsWith("file.js")), "longname file extracted");
  assert.equal(result.symlinks.length, 1, "symlink recorded");
  assert.ok(!existsSync(path.join(path.dirname(dest), "escape.txt")), "traversal refused");
  assert.ok(result.warnings.some((w) => w.includes("escapes")), "escape warning present");
});

// ---- Regression: danger-child-process false positives ----
test("danger-child-process ignores RegExp.exec and respects shell:false", () => {
  const semverCode = `
const semverRe = /^(\\d+)\\.(\\d+)\\.(\\d+)((?:-[0-9A-Za-z.-]+))?(?:\\+[0-9A-Za-z.-]+)?$/;
const match = semverRe.exec(value.trim());
if (match === null) return undefined;
return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]) };
`;
  const findings1 = analyzeSnippets({ "lib/semver.js": semverCode });
  assert.equal(findings1.filter((f) => f.id === "danger-child-process").length, 0, "RegExp-only file not flagged");

  const mixedCode = `
import { spawn } from "node:child_process";
const semverRe = /^(\\d+)\\.(\\d+)\\.(\\d+)$/;
const m1 = semverRe.exec(v1);
const m2 = semverRe.exec(v2);
const m3 = someOtherRegex.exec(v3);
function spawnShim(file, args, options) {
  return spawn(file, [...args], { ...options, shell: false });
}
`;
  const cpFindings = analyzeSnippets({ "lib/cli.js": mixedCode }).filter((f) => f.id === "danger-child-process");
  const execFalsePositives = cpFindings.filter((f) => f.message.includes("child_process.exec"));
  assert.equal(execFalsePositives.length, 0, "RegExp.exec not reported as child_process.exec");
  assert.ok(cpFindings.length >= 1, "real spawn() still flagged");
  assert.ok(cpFindings.every((f) => f.severity !== "critical"), "shell:false downgraded from critical");
});

test("danger-child-process still flags shell:true + template interpolation as critical", () => {
  const evilCode = `
import { exec } from "node:child_process";
function run(userInput) {
  exec(\`ls \${userInput}\`, { shell: true }, cb);
}
`;
  const critical = analyzeSnippets({ "lib/evil.js": evilCode })
    .filter((f) => f.id === "danger-child-process" && f.severity === "critical");
  assert.ok(critical.length >= 1, "critical finding present");
});

// ---- Regression: previously blocked plugins must not be blocked ----
test("previously blocked community plugins review to pass/warn", async () => {
  const targets = [
    ["dshmarket", path.join(profileNodeModules, "dshmarket")],
    ["@linxin666/dsh-remote-web-ui", path.join(profileNodeModules, "@linxin666", "dsh-remote-web-ui")],
    ["@linxin666/dsh-ssh", path.join(profileNodeModules, "@linxin666", "dsh-ssh")],
    ["@linxin666/dsh-client-ui-aionui-panel", path.join(profileNodeModules, "@linxin666", "dsh-client-ui-aionui-panel")]
  ];
  for (const [name, dir] of targets) {
    if (!existsSync(dir)) continue; // 未安装环境跳过
    const report = await analyzePackageDir(dir, { spec: name, source: "installed" });
    assert.notEqual(report.verdict, "block", name + " should not be blocked (score=" + report.score + ")");
  }
});

// ---- Regression: self review must not be blocked by own test fixtures ----
test("plugin self-review does not flag its own test fixtures as critical", async () => {
  const report = await analyzePackageDir(REPO_ROOT, { spec: "dsh-plugin-security-review", source: "installed" });
  assert.notEqual(report.verdict, "block", "self review verdict=" + report.verdict + " score=" + report.score);
});
