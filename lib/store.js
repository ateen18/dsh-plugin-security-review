import path from "node:path";
import os from "node:os";
import { existsSync, mkdirSync, readFileSync, writeFileSync, renameSync, statSync, readdirSync } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import { sha1Hex } from "./analyzer/util.js";
import { analyzePackageDir, renderReportMarkdown } from "./analyzer/index.js";

/**
 * Resolve the dsh home directory: $DSH_HOME, else ~/.dsh.
 */
export function resolveDshHome() {
  if (process.env.DSH_HOME) return process.env.DSH_HOME;
  const home = os.homedir();
  return path.join(home, ".dsh");
}

/** Sanitize a package name for use in file names. */
export function safeFileName(name) {
  return String(name ?? "unknown").replace(/[^A-Za-z0-9._@+-]/g, "_").slice(0, 120);
}

/**
 * Durable review storage under $DSH_HOME/security-review:
 *   cache/<name>-<hash>.json    verdict cache keyed by package identity
 *   reports/latest/<name>.md    newest markdown report per package
 *   reports/history/<name>-<ts>.json   full JSON reports
 *   index.json                  latest summary per package (for `list`)
 */
export class ReviewStore {
  constructor(root) {
    this.root = root ?? path.join(resolveDshHome(), "security-review");
    this.cacheDir = path.join(this.root, "cache");
    this.latestDir = path.join(this.root, "reports", "latest");
    this.historyDir = path.join(this.root, "reports", "history");
    this.indexFile = path.join(this.root, "index.json");
    this.reviewing = new Map();
  }

  ensureDirs() {
    mkdirSync(this.cacheDir, { recursive: true });
    mkdirSync(this.latestDir, { recursive: true });
    mkdirSync(this.historyDir, { recursive: true });
  }

  /**
   * Cheap package identity for the verdict cache: name@version plus the
   * newest mtime and the file count, so a rebuild without a version bump
   * still invalidates.
   */
  async identityOf(dir) {
    const pkgFile = path.join(dir, "package.json");
    let name = "unknown";
    let version = "0.0.0";
    if (existsSync(pkgFile)) {
      try {
        const pkg = JSON.parse(readFileSync(pkgFile, "utf8"));
        name = pkg.name ?? name;
        version = pkg.version ?? version;
      } catch {}
    }
    let newest = 0;
    let count = 0;
    try {
      const entries = await readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.name === "node_modules" || entry.name === ".git") continue;
        try {
          const info = await stat(path.join(dir, entry.name));
          if (info.isDirectory()) continue;
          count += 1;
          newest = Math.max(newest, info.mtimeMs);
        } catch {}
      }
    } catch {}
    return sha1Hex([name, version, count, Math.round(newest)].join("|"));
  }

  cachePath(dir, key) {
    return path.join(this.cacheDir, safeFileName(dir.split(/[\/\\]/).filter(Boolean).pop()) + "-" + key + ".json");
  }

  /** Read a cached report when it still matches the package identity. */
  async loadCached(dir) {
    const key = await this.identityOf(dir);
    const file = this.cachePath(dir, key);
    if (!existsSync(file)) return null;
    try {
      const report = JSON.parse(readFileSync(file, "utf8"));
      return { report, key, fresh: false };
    } catch {
      return null;
    }
  }

  /**
   * Review one installed package directory with verdict caching.
   * Returns { report, cached, key }. Never throws: failures return a
   * degraded report so the gate can keep operating.
   */
  async reviewPackage(dir, opts = {}) {
    const real = existsSync(dir) ? await import("node:fs").then((fs) => fs.realpathSync(dir)) : dir;
    if (this.reviewing.has(real)) return this.reviewing.get(real);
    const task = (async () => {
      try {
        if (!opts.fresh) {
          const cached = await this.loadCached(real);
          if (cached) return { report: cached.report, cached: true, key: cached.key };
        }
        const report = await analyzePackageDir(real, { spec: opts.spec, source: "installed", policy: opts.policy });
        await this.save(report);
        return { report, cached: false, key: await this.identityOf(real) };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          report: {
            schemaVersion: 1,
            target: { spec: opts.spec ?? real, name: opts.spec ?? path.basename(real), version: "?", source: "installed", dir: real },
            analyzedAt: new Date().toISOString(),
            durationMs: 0,
            filesScanned: 0,
            filesSkipped: 0,
            findings: [{ id: "review-error", severity: "high", category: "hygiene", file: "(reviewer)", message: "无法完成静态审查：" + message }],
            score: 40,
            verdict: "warn",
            reasons: ["审查器运行失败：" + message],
            recommendation: { action: "caution", text: "审查器未能完成分析，请人工检查该插件。", suggestedCommand: undefined }
          },
          cached: false,
          key: null
        };
      }
    })();
    this.reviewing.set(real, task);
    try {
      return await task;
    } finally {
      this.reviewing.delete(real);
    }
  }

  /** Persist a report: cache, latest markdown, history JSON, index. */
  async save(report) {
    this.ensureDirs();
    const name = safeFileName(report.target.name ?? "unknown");
    const key = report.target.dir ? await this.identityOf(report.target.dir) : null;
    if (key) {
      const cacheFile = this.cachePath(report.target.dir, key);
      this.atomicWrite(cacheFile, JSON.stringify(report, null, 2));
    }
    const markdown = renderReportMarkdown(report);
    this.atomicWrite(path.join(this.latestDir, name + ".md"), markdown);
    const stamp = report.analyzedAt.replace(/[:.]/g, "-");
    this.atomicWrite(path.join(this.historyDir, name + "-" + stamp + ".json"), JSON.stringify(report, null, 2));
    const index = this.readIndex();
    index[name] = {
      name: report.target.name,
      version: report.target.version,
      verdict: report.verdict,
      score: report.score,
      findings: report.findings.length,
      analyzedAt: report.analyzedAt,
      markdown: path.join(this.latestDir, name + ".md")
    };
    this.atomicWrite(this.indexFile, JSON.stringify(index, null, 2));
  }

  readIndex() {
    try {
      return JSON.parse(readFileSync(this.indexFile, "utf8"));
    } catch {
      return {};
    }
  }

  listReports() {
    return Object.values(this.readIndex());
  }

  readLatestMarkdown(name) {
    const file = path.join(this.latestDir, safeFileName(name) + ".md");
    return existsSync(file) ? readFileSync(file, "utf8") : null;
  }

  atomicWrite(file, content) {
    mkdirSync(path.dirname(file), { recursive: true });
    const tmp = file + ".tmp-" + process.pid + "-" + Date.now();
    writeFileSync(tmp, content, "utf8");
    renameSync(tmp, file);
  }
}
