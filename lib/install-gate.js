/**
 * Pre-install review gate for native `dsh plugin add` commands.
 *
 * The security plugin's runtime layers (import gate, boot audit, install
 * watcher) only operate during profile boot. But `dsh plugin --profile X
 * add Y` runs in "plugin mode" — it never boots the profile, so none of
 * those layers are active. This module patches dsh's bin.js to inject a
 * review hook before `runPlugin` is called, turning the native install
 * path into a "review-then-install" flow identical to `dsh-safe-plugin add`.
 *
 * Patch lifecycle:
 *  - apply() calls patchDshBin(dshRoot) once per boot; the patch persists
 *    on disk so future `dsh plugin add` invocations go through the gate.
 *  - Idempotent: re-patching detects existing markers and re-applies only
 *    if the surrounding bin.js changed (e.g. dsh was updated).
 *  - Fail-open: if the hook import fails (plugin uninstalled, moved, etc.),
 *    installation proceeds without review — the existing runtime gate and
 *    watcher remain as fallbacks.
 */

import path from "node:path";
import { existsSync, readFileSync, writeFileSync, renameSync, unlinkSync, realpathSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createInterface } from "node:readline/promises";
import { reviewSpec, renderReportMarkdown, DEFAULT_POLICY } from "./analyzer/index.js";
import { ReviewStore, resolveDshHome, safeFileName } from "./store.js";

const MARKER_START = "// security-review:install-gate:start";
const MARKER_END = "// security-review:install-gate:end";

/**
 * The absolute file:// URL of this module, resolved through symlinks so
 * pnpm store paths work correctly when imported from dsh's bin.js context.
 */
const SELF_URL = (() => {
  try {
    return pathToFileURL(realpathSync(fileURLToPath(import.meta.url))).href;
  } catch {
    return import.meta.url;
  }
})();

/**
 * Escape a string for use inside a RegExp.
 */
function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Build the hook code block to inject into dsh's bin.js.
 * The block is inserted right after `case "plugin": {`.
 */
/**
 * Build the hook code block to inject into dsh's bin.js.
 * The block is inserted right after `case "plugin": {`.
 * The catch branch self-cleans: if the plugin was uninstalled/moved and the
 * module import fails, the injected block removes itself from bin.js so the
 * native install path is restored (no leftover residue).
 */
function buildHookCode() {
  return [
    `\t\t${MARKER_START}`,
    `\t\ttry {`,
    `\t\t  const __sr = await import(${JSON.stringify(SELF_URL)});`,
    `\t\t  const __srResult = await __sr.preInstallReview(invocation.profile, invocation.args);`,
    `\t\t  if (__srResult.abort) { process.stderr.write(__srResult.message + "\\n"); process.exit(__srResult.exitCode); }`,
    `\t\t  if (__srResult.modifiedArgs) { invocation.args = __srResult.modifiedArgs; }`,
    `\t\t} catch (__srErr) {`,
    `\t\t  process.stderr.write("[security-review] install-gate error: " + String(__srErr?.message ?? __srErr) + "\\n");`,
    `\t\t  // self-clean: restore bin.js when the plugin is unavailable (does not depend on this module)`,
    `\t\t  try {`,
    `\t\t    const __fs2 = await import("node:fs");`,
    `\t\t    const __url2 = await import("node:url");`,
    `\t\t    const __bin2 = __url2.fileURLToPath(import.meta.url);`,
    `\t\t    const __src2 = __fs2.readFileSync(__bin2, "utf8");`,
    `\t\t    const __s2 = "// security-review:install-gate:start";`,
    `\t\t    const __e2 = "// security-review:install-gate:end";`,
    `\t\t    const __i1 = __src2.indexOf(__s2);`,
    `\t\t    const __i2 = __src2.indexOf(__e2, __i1);`,
    `\t\t    if (__i1 >= 0 && __i2 > __i1) {`,
    `\t\t      __fs2.writeFileSync(__bin2, __src2.slice(0, __i1) + __src2.slice(__i2 + __e2.length), "utf8");`,
    `\t\t      process.stderr.write("[security-review] install-gate self-removed (plugin unavailable)\\n");`,
    `\t\t    }`,
    `\t\t  } catch {}`,
    `\t\t}`,
    `\t\t${MARKER_END}`,
  ].join("\n");
}

/**
 * Atomically replace bin.js: write a temp file, syntax-check it with
 * node --check (ESM), then rename over the original. On any failure the
 * original file is left untouched.
 */
function writeBinAtomically(binPath, content) {
  const tmp = path.join(path.dirname(binPath), "bin.sr-tmp-" + process.pid + "-" + Date.now() + ".mjs");
  try {
    writeFileSync(tmp, content, "utf8");
    const check = spawnSync(process.execPath, ["--check", tmp], { encoding: "utf8", timeout: 15000 });
    if (check.error || check.status !== 0) {
      const detail = String(check.stderr || check.error?.message || "unknown").slice(0, 300);
      return { ok: false, reason: "syntax check failed: " + detail };
    }
    renameSync(tmp, binPath);
    return { ok: true };
  } catch (error) {
    return { ok: false, reason: String(error?.message ?? error) };
  } finally {
    try { if (existsSync(tmp)) unlinkSync(tmp); } catch {}
  }
}

/**
 * Strip any existing patch block and collapse stray blank lines left after
 * the plugin case opener, so repeated inject/remove cycles do not litter.
 */
function stripExistingPatch(src, pluginCaseRegex) {
  let out = src;
  if (out.includes(MARKER_START)) {
    // Anchor markers to line start so the marker string literals embedded in
    // the self-clean block (e.g. `__s2 = "// security-review:install-gate:start"`)
    // are not mistaken for the real marker comments — otherwise the non-greedy
    // match spans only part of the block and leaves dangling code.
    const stripRe = new RegExp(
      "^[ \\t]*" + escapeRegex(MARKER_START) + "[\\s\\S]*?" + "^[ \\t]*" + escapeRegex(MARKER_END) + "\\n?",
      "gm"
    );
    out = out.replace(stripRe, "");
  }
  const m = pluginCaseRegex.exec(out);
  if (m) {
    let pos = m.index + m[0].length;
    while (out[pos] === "\n" || out[pos] === "\r") pos += 1;
    out = out.slice(0, m.index + m[0].length) + "\n" + out.slice(pos);
  }
  return out;
}

/**
 * Ensure dsh's bin.js carries the install-gate hook.
 *
 * Low-frequency by design: if the hook is already present AND points at the
 * current module URL, nothing is written (no per-boot rewrite of the global
 * dsh installation). Re-injection happens only when the hook is missing
 * (dsh updated) or stale (this plugin moved/reinstalled). Writes are atomic
 * and syntax-checked before replacing the original.
 *
 * Returns { patched, binPath?, written?, reason? }.
 */
export function patchDshBin(dshRoot) {
  if (!dshRoot) return { patched: false, reason: "no dsh root" };
  const binPath = path.join(dshRoot, "lib", "bin.js");
  if (!existsSync(binPath)) return { patched: false, reason: "bin.js not found at " + binPath };

  let src = readFileSync(binPath, "utf8");
  const pluginCaseRegex = /case\s+["']plugin["']\s*:\s*\{/;
  const match = pluginCaseRegex.exec(src);
  if (!match) return { patched: false, reason: "plugin case not found in bin.js (structure changed?)" };

  // Already injected and pointing at this module -> nothing to do.
  if (src.includes(MARKER_START) && src.includes(JSON.stringify(SELF_URL))) {
    return { patched: true, binPath, written: false };
  }

  const cleaned = stripExistingPatch(src, pluginCaseRegex);
  const m2 = pluginCaseRegex.exec(cleaned);
  if (!m2) return { patched: false, reason: "plugin case not found after strip" };
  const insertPos = m2.index + m2[0].length;
  const patched = cleaned.slice(0, insertPos) + "\n" + buildHookCode() + "\n" + cleaned.slice(insertPos);

  const written = writeBinAtomically(binPath, patched);
  if (!written.ok) return { patched: false, binPath, reason: written.reason };
  return { patched: true, binPath, written: true };
}

/**
 * Remove the install-gate patch from dsh's bin.js (uninstall or debug).
 * Also atomic + syntax-checked; returns true when a removal happened.
 */
export function unpatchDshBin(dshRoot) {
  if (!dshRoot) return false;
  const binPath = path.join(dshRoot, "lib", "bin.js");
  if (!existsSync(binPath)) return false;
  const src = readFileSync(binPath, "utf8");
  if (!src.includes(MARKER_START)) return false;
  const pluginCaseRegex = /case\s+["']plugin["']\s*:\s*\{/;
  const cleaned = stripExistingPatch(src, pluginCaseRegex);
  const written = writeBinAtomically(binPath, cleaned);
  return written.ok;
}

export function isPatched(dshRoot) {
  if (!dshRoot) return false;
  const binPath = path.join(dshRoot, "lib", "bin.js");
  if (!existsSync(binPath)) return false;
  return readFileSync(binPath, "utf8").includes(MARKER_START);
}

// ─── preInstallReview ─────────────────────────────────────────────

/**
 * Extract package specs from pnpm args.
 * pnpm add args: ["add", "pkg-a", "pkg-b@1.0.0", "-D", "pkg-c"]
 * Returns { specs: ["pkg-a", "pkg-b@1.0.0", "pkg-c"], skip: false }.
 */
function parseAddSpecs(args) {
  // Find the "add" subcommand position
  const addIdx = args.indexOf("add");
  if (addIdx === -1) return { specs: [], isAdd: false };

  const specs = [];
  for (let i = addIdx + 1; i < args.length; i++) {
    const arg = args[i];
    // Skip flags (pnpm options like -D, --save-dev, --ignore-scripts, etc.)
    if (arg.startsWith("-")) continue;
    // Skip pnpm subcommand keywords
    if (["add", "remove", "install", "update", "why"].includes(arg)) continue;
    specs.push(arg);
  }
  return { specs, isAdd: true };
}

/**
 * Interactive [y/N] prompt for warn verdicts. Returns true if confirmed.
 * In non-TTY environments (pipes, CI), returns false (abort by default).
 */
async function confirmInstall(prompt) {
  if (!process.stdin.isTTY) {
    process.stderr.write("[security-review] non-interactive environment, warn requires --sr-skip or --sr-force-warn to proceed.\n");
    return false;
  }
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = await rl.question(prompt);
    return /^\s*(y|yes|是)\s*$/i.test(answer);
  } finally {
    rl.close();
  }
}

/**
 * Pre-install review gate. Called by the patched dsh bin.js before runPlugin.
 *
 * Returns { abort: false } to proceed, or
 * { abort: true, message, exitCode } to abort the installation.
 *
 * For add commands:
 *  - Downloads & statically reviews each package spec before installation.
 *  - pass → proceed (auto-attach --ignore-scripts).
 *  - warn → TTY: interactive [y/N] prompt; non-TTY: abort unless --sr-force-warn.
 *  - block → abort (exit 2) unless --sr-skip or --sr-force-warn.
 *  - --sr-skip bypasses the gate entirely (power user escape hatch).
 *
 * For non-add commands (remove, update, why, install): no review, proceed.
 */
export async function preInstallReview(profile, args) {
  if (!Array.isArray(args) || args.length === 0) return { abort: false };

  // Power-user escape hatch: --sr-skip bypasses all review.
  if (args.includes("--sr-skip")) {
    process.stderr.write("[security-review] install-gate skipped (--sr-skip).\n");
    return { abort: false, modifiedArgs: args.filter((a) => a !== "--sr-skip") };
  }

  // --sr-force-warn: allow warn/block to proceed with a warning.
  const forceWarn = args.includes("--sr-force-warn");
  const cleanArgs = args.filter((a) => a !== "--sr-force-warn" && a !== "--sr-skip");

  const { specs, isAdd } = parseAddSpecs(cleanArgs);
  if (!isAdd || specs.length === 0) return { abort: false };

  // Build modified args: add --ignore-scripts if not present (prevents
  // lifecycle scripts from running during install — same safety measure
  // as dsh-safe-plugin add).
  let modifiedArgs = cleanArgs;
  if (!cleanArgs.includes("--ignore-scripts") && !cleanArgs.includes("--ignore-scripts=true")) {
    modifiedArgs = [...cleanArgs, "--ignore-scripts"];
  }

  // Review each spec; the most severe verdict across all specs wins.
  let worstVerdict = "pass";
  let worstScore = 100;
  const reports = [];

  for (const spec of specs) {
    process.stderr.write("[security-review] reviewing " + spec + " ...\n");
    try {
      const { report } = await reviewSpec(spec, {
        policy: DEFAULT_POLICY,
        cwd: process.cwd(),
      });
      reports.push({ spec, report });

      // Print the full report to stderr
      process.stderr.write(renderReportMarkdown(report) + "\n");

      const rank = { pass: 0, warn: 1, block: 2 };
      if (rank[report.verdict] > rank[worstVerdict]) {
        worstVerdict = report.verdict;
        worstScore = report.score;
      } else if (report.verdict === worstVerdict && report.score < worstScore) {
        worstScore = report.score;
      }
    } catch (error) {
      // Review failed — fail open (proceed) but log the error.
      process.stderr.write(
        "[security-review] review of " + spec + " failed: " +
        String(error?.message ?? error) + "\n"
      );
      process.stderr.write("[security-review] proceeding (fail-open). The runtime gate and watcher remain active.\n");
      return { abort: false, modifiedArgs };
    }
  }

  // Decision based on worst verdict.
  if (worstVerdict === "block" && !forceWarn) {
    const names = reports.map((r) => r.spec).join(", ");
    return {
      abort: true,
      message:
        "[security-review] verdict: block (score " + worstScore + "). " +
        "Installation of " + names + " cancelled.\n" +
        "[security-review] Review the report above. To proceed at your own risk, re-run with --sr-force-warn.",
      exitCode: 2,
    };
  }

  if (worstVerdict === "warn") {
    if (forceWarn) {
      process.stderr.write("[security-review] verdict: warn (score " + worstScore + "), proceeding (--sr-force-warn).\n");
    } else {
      const confirmed = await confirmInstall(
        "[security-review] verdict: warn (score " + worstScore + "). Install anyway? [y/N] "
      );
      if (!confirmed) {
        return {
          abort: true,
          message: "[security-review] installation cancelled by user.",
          exitCode: 3,
        };
      }
    }
  }

  if (worstVerdict === "pass") {
    process.stderr.write(
      "[security-review] verdict: pass (score " + worstScore + "). Proceeding with installation.\n"
    );
  }

  // Persist reports to the review store.
  try {
    const store = new ReviewStore();
    for (const { report } of reports) {
      await store.save(report);
    }
  } catch {
    // non-fatal — store failures don't block installation
  }

  return { abort: false, modifiedArgs };
}