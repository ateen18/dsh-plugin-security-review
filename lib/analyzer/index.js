import path from "node:path";
import os from "node:os";
import { mkdtempSync, rmSync, existsSync, realpathSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { collectFiles, readTextFile, readPackageJson, TEXT_EXTS } from "./files.js";
import { runRules } from "./rules.js";
import { scoreFindings, verdictFor, DEFAULT_POLICY, LABELS } from "./score.js";
import { renderReportMarkdown } from "./render.js";
import { extractTgz } from "./tar.js";
import { classifySpec, resolveRegistrySpec, downloadTarball } from "./registry.js";

/**
 * Analyze one package directory (async). The analyzer is pure static
 * analysis: it never executes package code.
 */
export async function analyzePackageDir(dir, opts = {}) {
  const startedAt = Date.now();
  const real = existsSync(dir) ? realpathSync(dir) : dir;
  const packageJson = readPackageJson(real) ?? {};
  const name = packageJson.name ?? opts.name ?? path.basename(real);
  const version = packageJson.version ?? opts.version ?? "?";
  const collected = await collectFiles(real, { ...opts.caps, ignore: opts.ignore });
  const textByRel = new Map();
  const files = [];
  let scannedBytes = 0;
  for (const file of collected.files) {
    const text = readTextFile(file.abs);
    if (text == null) {
      collected.skipped.push({ rel: file.rel, reason: "binary" });
      continue;
    }
    textByRel.set(file.rel, text);
    files.push(file);
    scannedBytes += file.bytes;
  }
  const ctx = {
    packageJson,
    meta: { name, version, source: opts.source ?? "path", spec: opts.spec ?? name },
    filePaths: files.map((f) => f.rel),
    textByRel,
    files,
    binary: collected.binary,
    counters: {}
  };
  const findings = runRules(ctx);
  for (const extra of opts.extraFindings ?? []) findings.push(extra);
  const score = scoreFindings(findings);
  const report = {
    schemaVersion: 1,
    target: {
      spec: opts.spec ?? (name + "@" + version),
      name,
      version,
      source: opts.source ?? "path",
      dir: real,
      files: files.length,
      bytes: collected.totalBytes
    },
    analyzedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    filesScanned: files.length,
    filesSkipped: collected.skipped.length,
    skipped: collected.skipped.slice(0, 50),
    binary: collected.binary.slice(0, 50),
    findings,
    score
  };
  const decision = verdictFor(report, opts.policy ?? DEFAULT_POLICY);
  report.verdict = decision.verdict;
  report.reasons = decision.reasons;
  report.recommendation = recommendationFor(report, decision);
  return report;
}

/** Recommendation text per verdict. */
function recommendationFor(report, decision) {
  const texts = {
    install: "未发现明显风险，可以安装。仍建议通过 dsh-safe-plugin add 安装，安装时跳过生命周期脚本。",
    caution: "存在需要人工确认的发现。建议逐条审查后，在知情的前提下安装；运行时门禁会持续审计并记录。",
    block: "存在严重/高危风险，不建议安装。若确需使用，请先逐条人工审查全部发现，确认可信后再考虑放行。",
    audit: "当前为仅审计模式：不拦截，仅记录报告。"
  };
  return {
    action: decision.action,
    text: texts[decision.action] ?? texts.audit,
    suggestedCommand: decision.suggestedCommand ?? ("dsh-safe-plugin add " + report.target.name)
  };
}

/**
 * Analyze a .tar.gz buffer: extract into a temp dir, analyze, clean up.
 */
export async function analyzeTarball(buffer, opts = {}) {
  const tmp = mkdtempSync(path.join(os.tmpdir(), "dsh-review-"));
  try {
    const extracted = extractTgz(buffer, tmp, opts.caps);
    const report = await analyzePackageDir(tmp, {
      ...opts,
      source: opts.source ?? "registry",
      extraFindings: [
        ...(opts.extraFindings ?? []),
        ...extracted.symlinks.slice(0, 3).map((link) => ({
          id: "tar-symlink",
          severity: "low",
          category: "supply-chain",
          file: "(tarball)",
          message: "包内包含符号链接：" + link.name + " -> " + link.linkname
        })),
        ...extracted.warnings.slice(0, 3).map((warning) => ({
          id: "tar-warning",
          severity: "info",
          category: "supply-chain",
          file: "(tarball)",
          message: "解包警告：" + warning
        }))
      ]
    });
    return report;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * Clone a git spec into destDir without running any package scripts.
 */
export function cloneGitSpec(spec, destDir) {
  const url = String(spec).replace(/^git\+/, "").replace(/#.*$/, "");
  const result = spawnSync("git", ["clone", "--depth", "1", url, destDir], { stdio: "pipe", timeout: 120000 });
  if (result.error || result.status !== 0) {
    const detail = result.error?.message ?? String(result.stderr ?? "").slice(0, 500);
    throw new Error("git clone failed: " + detail);
  }
  return destDir;
}

/**
 * Review any spec (registry name@range, tarball url, git url, or local
 * path). Returns { report, kind }.
 */
export async function reviewSpec(spec, opts = {}) {
  const kind = classifySpec(spec);
  if (kind === "file") {
    const rawPath = String(spec).replace(/^file:/i, "").replace(/^link:/i, "");
    const dir = path.isAbsolute(rawPath) ? rawPath : path.resolve(opts.cwd ?? process.cwd(), rawPath);
    if (!existsSync(path.join(dir, "package.json"))) {
      throw new Error("path is not a package directory (no package.json): " + dir);
    }
    return { kind, report: await analyzePackageDir(dir, { ...opts, spec, source: "path" }) };
  }
  if (kind === "registry") {
    const resolved = await resolveRegistrySpec(spec, opts.registry);
    const downloaded = await downloadTarball(resolved.tarballUrl, { integrity: resolved.integrity, shasum: resolved.shasum });
    const extraFindings = [];
    if (resolved.integrity && !downloaded.integrityOk) {
      extraFindings.push({
        id: "integrity-mismatch",
        severity: "critical",
        category: "supply-chain",
        file: "(tarball)",
        message: "tarball 完整性校验失败：内容与 registry 记录的 sha512 不一致，可能被篡改",
        recommendation: "不要安装；联系发布者或换用其他版本"
      });
    }
    const report = await analyzeTarball(downloaded.buffer, {
      ...opts,
      spec,
      name: resolved.name,
      version: resolved.version,
      source: "registry",
      extraFindings
    });
    if (resolved.note) {
      report.findings.push({ id: "registry-note", severity: "info", category: "supply-chain", file: "(registry)", message: resolved.note });
    }
    return { kind, report };
  }
  if (kind === "url") {
    const downloaded = await downloadTarball(spec);
    return { kind, report: await analyzeTarball(downloaded.buffer, { ...opts, spec, source: "url" }) };
  }
  const tmp = mkdtempSync(path.join(os.tmpdir(), "dsh-git-"));
  try {
    cloneGitSpec(spec, tmp);
    return { kind, report: await analyzePackageDir(tmp, { ...opts, spec, source: "git" }) };
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

export { renderReportMarkdown, verdictFor, DEFAULT_POLICY, LABELS };
export { classifySpec, resolveRegistrySpec, downloadTarball } from "./registry.js";
