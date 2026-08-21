#!/usr/bin/env node
import path from "node:path";
import { createRequire } from "node:module";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createInterface } from "node:readline/promises";
import { reviewSpec, analyzePackageDir, renderReportMarkdown, DEFAULT_POLICY } from "../analyzer/index.js";
import { normalizeGitSpecForPnpm } from "../analyzer/registry.js";
import { ReviewStore, resolveDshHome, safeFileName } from "../store.js";

const VERSION = "0.1.0";

const HELP = [
  "dsh-safe-plugin - DSH plugin security review gate",
  "",
  "usage:",
  "  dsh-safe-plugin add <spec>      review then install (forwards to dsh plugin add)",
  "  dsh-safe-plugin review <spec>   review only, print the report",
  "  dsh-safe-plugin list            list historical reports",
  "  dsh-safe-plugin verify [name]   re-review installed plugins",
  "  dsh-safe-plugin install-gate [--dsh-root <dir>]    inject install gate into dsh bin.js",
  "  dsh-safe-plugin uninstall-gate [--dsh-root <dir>]  remove install gate from dsh bin.js",
  "",
  "spec: npm name(@version) | local dir | git url | .tgz url",
  "",
  "options:",
  "  --profile <name>   dsh profile (default web)",
  "  --yes, -y          auto-confirm warnings (CI)",
  "  --force, -f        install even when verdict is block (dangerous)",
  "  --json             print JSON report",
  "  --registry <url>   override npm registry",
  "  --ignore <pattern> skip files whose path contains pattern (repeatable)",
  "  --help, -h         help",
  ""
].join("\n");

function fail(message, code = 1) {
  process.stderr.write("dsh-safe-plugin: " + message + "\n");
  process.exit(code);
}

function parseArgs(argv) {
  const flags = { profile: "web", yes: false, force: false, json: false, registry: undefined, ignore: [], dshRoot: undefined };
  const rest = [];
  let command = null;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--profile") { flags.profile = argv[++i]; continue; }
    if (arg.startsWith("--profile=")) { flags.profile = arg.slice(10); continue; }
    if (arg === "--registry") { flags.registry = argv[++i]; continue; }
    if (arg === "--dsh-root") { flags.dshRoot = argv[++i]; continue; }
    if (arg.startsWith("--registry=")) { flags.registry = arg.slice(11); continue; }
    if (arg === "--yes" || arg === "-y") { flags.yes = true; continue; }
    if (arg === "--force" || arg === "-f") { flags.force = true; continue; }
    if (arg === "--json") { flags.json = true; continue; }
    if (arg === "--ignore") { flags.ignore.push(argv[++i]); continue; }
    if (arg.startsWith("--ignore=")) { flags.ignore.push(arg.slice(9)); continue; }
    if (arg === "--help" || arg === "-h") { process.stdout.write(HELP); process.exit(0); }
    if (arg === "--version" || arg === "-V") { process.stdout.write(VERSION + "\n"); process.exit(0); }
    if (arg.startsWith("-") && command === null) fail("unknown option: " + arg);
    if (command === null) { command = arg; continue; }
    rest.push(arg);
  }
  return { command: command ?? "help", flags, rest };
}

function profileDir(profile) {
  return path.join(resolveDshHome(), "profiles", profile);
}

async function confirm(prompt) {
  if (!process.stdin.isTTY) return null;
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = await rl.question(prompt);
    return /^\s*(y|yes|是)\s*$/i.test(answer);
  } finally {
    rl.close();
  }
}

function printReport(report, json) {
  if (json) {
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
    return;
  }
  process.stdout.write(renderReportMarkdown(report) + "\n");
}

function profileDeps(profile) {
  const file = path.join(profileDir(profile), "package.json");
  if (!existsSync(file)) return {};
  try {
    return JSON.parse(readFileSync(file, "utf8")).dependencies ?? {};
  } catch {
    return {};
  }
}

async function runAdd(args) {
  const spec = args.rest[0];
  if (!spec) fail("add needs a package spec");
  process.stderr.write("dsh-safe-plugin: reviewing " + spec + " ...\n");
  const { report } = await reviewSpec(spec, { registry: args.flags.registry, policy: DEFAULT_POLICY, ignore: args.flags.ignore });
  printReport(report, args.flags.json);
  if (report.verdict === "block" && !args.flags.force) {
    fail("verdict is block, install cancelled; review the report first (--force overrides, not recommended)", 2);
  }
  if (report.verdict === "block" && args.flags.force) {
    process.stderr.write("dsh-safe-plugin: WARNING: verdict is block, installing with --force at your own risk\n");
  }
  if (report.verdict === "warn" && !args.flags.yes) {
    const ok = await confirm("findings need human review, install anyway? [y/N] ");
    if (ok !== true) fail("install cancelled (use --yes to skip the prompt)", 3);
  }
  const before = profileDeps(args.flags.profile);
  const installSpec = normalizeGitSpecForPnpm(spec);
  const dshArgs = ["plugin", "--profile", args.flags.profile, "add", installSpec, "--ignore-scripts"];
  process.stderr.write("dsh-safe-plugin: running dsh " + dshArgs.join(" ") + "\n");
  const result = spawnSync("dsh", dshArgs, { stdio: "inherit", shell: process.platform === "win32" });
  if (result.error) fail("cannot start dsh: " + result.error.message + " (is dsh on PATH?)", 4);
  const code = result.status ?? 1;
  if (code !== 0) fail("dsh plugin add failed (exit " + code + ")", 4);
  const after = profileDeps(args.flags.profile);
  const added = Object.keys(after).filter((name) => !(name in before));
  const store = new ReviewStore();
  let installedVerdict = report.verdict;
  for (const name of added) {
    try {
      const req = createRequire(path.join(profileDir(args.flags.profile), "package.json"));
      const resolved = realpathSync(path.dirname(req.resolve(name + "/package.json")));
      const installed = await analyzePackageDir(resolved, { spec: name, source: "installed", policy: DEFAULT_POLICY });
      await store.save(installed);
      installedVerdict = installed.verdict;
      process.stderr.write("dsh-safe-plugin: installed-content re-review verdict: " + installed.verdict + " (score " + installed.score + ")\n");
      if (installed.verdict === "block") {
        process.stderr.write("dsh-safe-plugin: WARNING: installed content re-review verdict is block! disable it immediately (see report)\n");
      }
    } catch (error) {
      process.stderr.write("dsh-safe-plugin: post-install re-review failed: " + String(error?.message ?? error) + "\n");
    }
  }
  process.stderr.write("dsh-safe-plugin: done. latest report: " + path.join(store.latestDir, safeFileName(report.target.name) + ".md") + "\n");
  process.exit(installedVerdict === "block" ? 2 : 0);
}

async function runReview(args) {
  const spec = args.rest[0];
  if (!spec) fail("review needs a package spec");
  process.stderr.write("dsh-safe-plugin: reviewing " + spec + " ...\n");
  const { report } = await reviewSpec(spec, { registry: args.flags.registry, policy: DEFAULT_POLICY, ignore: args.flags.ignore });
  printReport(report, args.flags.json);
  process.stderr.write("dsh-safe-plugin: verdict " + report.verdict + " (score " + report.score + ")\n");
  process.exit(0);
}

function runList() {
  const store = new ReviewStore();
  const reports = store.listReports();
  if (!reports.length) {
    process.stdout.write("no reports yet. run: dsh-safe-plugin review <spec>\n");
    process.exit(0);
  }
  process.stdout.write("reviewed packages:\n");
  for (const row of reports) {
    const verdict = row.verdict ?? "?";
    const score = row.score ?? "?";
    const findings = row.findings ?? 0;
    process.stdout.write("  " + (row.name ?? "?") + " @ " + (row.version ?? "?") + "  " + verdict + " (score " + score + ", " + findings + " findings)\n");
    process.stdout.write("    report: " + (row.markdown ?? "") + "\n");
  }
  process.exit(0);
}

async function runVerify(args) {
  const name = args.rest[0];
  const store = new ReviewStore();
  const profile = args.flags.profile;
  const candidates = name ? [name] : Object.keys(profileDeps(profile));
  if (!candidates.length) fail("profile " + profile + " has no dependencies to verify");
  for (const candidate of candidates) {
    try {
      const req = createRequire(path.join(profileDir(profile), "package.json"));
      const resolved = realpathSync(path.dirname(req.resolve(candidate + "/package.json")));
      const report = await analyzePackageDir(resolved, { spec: candidate, source: "installed", policy: DEFAULT_POLICY, ignore: args.flags.ignore });
      await store.save(report);
      printReport(report, args.flags.json);
      process.stderr.write("dsh-safe-plugin: " + candidate + " verdict " + report.verdict + " (score " + report.score + ")\n");
    } catch (error) {
      process.stderr.write("dsh-safe-plugin: verify " + candidate + " failed: " + String(error?.message ?? error) + "\n");
    }
  }
  process.exit(0);
}

function dshRootFromFlags(flags) {
  if (flags.dshRoot) return flags.dshRoot;
  try {
    const req = createRequire(import.meta.url);
    const anchor = req.resolve("@deepseek-ai/dsh/package.json");
    return requireNodePathDirname(anchor);
  } catch {
    return null;
  }
}
function requireNodePathDirname(p) {
  return p.slice(0, Math.max(p.lastIndexOf("\\"), p.lastIndexOf("/")));
}
function runInstallGate(command, flags) {
  const root = dshRootFromFlags(flags);
  if (!root) {
    process.stderr.write("dsh-safe-plugin: 找不到 dsh 安装根目录（可传 --dsh-root <dir>）\n");
    process.exit(1);
  }
  void import("../install-gate.js").then((gate) => {
    if (command === "install-gate") {
      const result = gate.patchDshBin(root);
      if (result.patched) {
        process.stderr.write("dsh-safe-plugin: install-gate 已" + (result.written ? "注入" : "生效（无需重写）") + "（" + result.binPath + "）\n");
        process.exit(0);
      }
      process.stderr.write("dsh-safe-plugin: install-gate 注入失败：" + (result.reason ?? "未知") + "\n");
      process.exit(1);
    }
    const removed = gate.unpatchDshBin(root);
    process.stderr.write(removed ? "dsh-safe-plugin: 已移除 install-gate 注入\n" : "dsh-safe-plugin: bin.js 中没有 install-gate 注入，无需清理\n");
    process.exit(0);
  }).catch((error) => {
    process.stderr.write("dsh-safe-plugin: " + String(error?.message ?? error) + "\n");
    process.exit(1);
  });
}

async function main() {
  const { command, flags, rest } = parseArgs(process.argv.slice(2));
  const args = { flags, rest };
  if (command === "add") await runAdd(args);
  else if (command === "review") await runReview(args);
  else if (command === "list") runList();
  else if (command === "verify") await runVerify(args);
  else if (command === "install-gate" || command === "uninstall-gate") runInstallGate(command, args.flags);
  else { process.stdout.write(HELP); process.exit(1); }
}

main().catch((error) => {
  process.stderr.write("dsh-safe-plugin: " + (error?.stack ?? String(error)) + "\n");
  process.exit(1);
});
