import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import os from "node:os";
import { mkdtempSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { gunzipSync, gzipSync } from "node:zlib";
import { analyzePackageDir, verdictFor, renderReportMarkdown } from "../lib/analyzer/index.js";
import { scoreFindings, DEFAULT_POLICY } from "../lib/analyzer/score.js";
import { selectVersion, parseVersion, satisfiesClause } from "../lib/analyzer/semver.js";
import { nearMiss, KNOWN_NAMES } from "../lib/analyzer/known.js";
import { extractTgz } from "../lib/analyzer/tar.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EVIL = path.join(HERE, "fixtures", "evil-plugin");
const BENIGN = path.join(HERE, "fixtures", "benign-plugin");

test("evil fixture is blocked with expected findings", async () => {
  const report = await analyzePackageDir(EVIL, { spec: "evil-plugin" });
  const ids = new Set(report.findings.map((f) => f.id));
  assert.equal(report.verdict, "block");
  assert.ok(report.score < 40, "score should be low, got " + report.score);
  assert.ok(ids.has("install-script"), "install-script missing");
  assert.ok(ids.has("danger-child-process"), "danger-child-process missing");
  assert.ok(ids.has("data-exfil"), "data-exfil missing");
  assert.ok(ids.has("hardcoded-secret"), "hardcoded-secret missing");
  assert.ok(ids.has("dynamic-eval"), "dynamic-eval missing");
  assert.ok(ids.has("plain-http"), "plain-http missing");
  assert.ok(ids.has("suspicious-deps"), "suspicious-deps missing");
  assert.ok(ids.has("weak-metadata"), "weak-metadata missing");
  const postinstall = report.findings.find((f) => f.id === "install-script");
  assert.equal(postinstall.severity, "critical");
});

test("benign fixture passes", async () => {
  const report = await analyzePackageDir(BENIGN, { spec: "benign-plugin" });
  assert.equal(report.verdict, "pass");
  assert.ok(report.score >= 70, "score " + report.score);
  for (const f of report.findings) {
    assert.notEqual(f.severity, "critical");
    assert.notEqual(f.severity, "high");
  }
});

test("verdict policy modes", () => {
  const base = { target: { name: "x" }, score: 90, findings: [] };
  assert.equal(verdictFor(base, DEFAULT_POLICY).verdict, "pass");
  const withHigh = { ...base, findings: [{ id: "a", severity: "high" }] };
  assert.equal(verdictFor(withHigh, { ...DEFAULT_POLICY, mode: "standard" }).verdict, "warn");
  assert.equal(verdictFor(withHigh, { ...DEFAULT_POLICY, mode: "strict" }).verdict, "block");
  const withCritical = { ...base, findings: [{ id: "b", severity: "critical" }] };
  assert.equal(verdictFor(withCritical, { ...DEFAULT_POLICY }).verdict, "block");
  assert.equal(verdictFor(withCritical, { ...DEFAULT_POLICY, allowlist: ["x"] }).verdict, "pass");
  assert.equal(verdictFor(withCritical, { ...DEFAULT_POLICY, mode: "audit-only" }).verdict, "audit");
});

test("scoreFindings", () => {
  assert.equal(scoreFindings([]), 100);
  assert.equal(scoreFindings([{ severity: "critical" }]), 45);
  assert.equal(scoreFindings([{ severity: "high" }]), 82);
  assert.ok(scoreFindings([{ severity: "critical" }, { severity: "critical" }, { severity: "critical" }]) < 40);
});

test("semver basics", () => {
  assert.deepEqual(parseVersion("v1.2.3"), { major: 1, minor: 2, patch: 3, prerelease: null });
  assert.equal(satisfiesClause("^1.2.3", "1.9.9"), true);
  assert.equal(satisfiesClause("^1.2.3", "2.0.0"), false);
  assert.equal(satisfiesClause("~1.2.3", "1.2.9"), true);
  assert.equal(satisfiesClause("~1.2.3", "1.3.0"), false);
  assert.equal(satisfiesClause(">=2", "2.5.0"), true);
  const pick = selectVersion(["1.0.0", "1.2.0", "1.2.5", "2.0.0"], "^1.2.0");
  assert.equal(pick.version, "1.2.5");
});

test("typosquat nearMiss", () => {
  assert.equal(nearMiss("dsh-pets", "dsh-pet"), 1);
  assert.equal(nearMiss("react", "react"), 0);
  assert.equal(nearMiss("react-dom", "react"), 2);
  assert.ok(KNOWN_NAMES.has("@linxin666/dsh-pet"));
});

test("report markdown renders", async () => {
  const report = await analyzePackageDir(BENIGN, { spec: "benign-plugin" });
  const md = renderReportMarkdown(report);
  assert.ok(md.includes("安全审查报告"));
  assert.ok(md.includes("安装命令"));
});

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

test("extractTgz roundtrip + longname + traversal refusal", () => {
  const dest = mkdtempSync(path.join(os.tmpdir(), "dsh-review-test-"));
  const longName = "packages/" + "a".repeat(110) + "/file.js";
  const tgz = makeTgz([
    { name: "package/package.json", content: "{}" },
    { type: "L", name: longName },
    { name: "short.js", content: "export const x = 1;" },
    { name: "../../escape.txt", content: "evil" },
    { name: "package/link", type: "2", linkname: "../outside" }
  ]);
  const result = extractTgz(tgz, dest);
  assert.ok(result.files.some((f) => f.endsWith("package.json")));
  assert.ok(result.files.some((f) => f.endsWith("file.js")));
  assert.equal(result.symlinks.length, 1);
  assert.ok(!existsSync(path.join(path.dirname(dest), "escape.txt")));
  assert.ok(result.warnings.some((w) => w.includes("escapes")));
});

test("gunzip roundtrip sanity", () => {
  const buf = Buffer.from("hello");
  assert.equal(gunzipSync(gzipSync(buf)).toString(), "hello");
});
