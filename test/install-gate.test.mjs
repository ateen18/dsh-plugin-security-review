import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync, mkdtempSync, rmSync, mkdirSync } from "node:fs";
import path from "node:path";
import os from "node:os";

// We need to test patchDshBin/unpatchDshBin/isPatched against a mock bin.js,
// and preInstallReview's arg parsing / verdict logic. The reviewSpec call
// inside preInstallReview makes network requests, so we test the arg-parsing
// and decision logic by mocking reviewSpec where needed.

// ─── Helper: create a mock dsh root with a bin.js ──────────────────

const MOCK_BIN_TEMPLATE = `#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
function readVersion() {
  const manifest = JSON.parse(readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8"));
  return typeof manifest.version === "string" ? manifest.version : "0.0.0";
}
const invocation = { mode: "plugin", profile: "web", args: process.argv.slice(2) };
switch (invocation.mode) {
\tcase "plugin": {
\t\tconst { runPlugin } = await import("./plugin-hash.js");
\t\tprocess.exit(runPlugin(invocation.profile, invocation.args));
\t\tbreak;
\t}
\tdefault: throw new Error("unhandled mode " + invocation.mode);
}
`;

function createMockDshRoot() {
  const tmp = mkdtempSync(path.join(os.tmpdir(), "dsh-mock-"));
  const libDir = path.join(tmp, "lib");
  writeFileSync(path.join(tmp, "package.json"), JSON.stringify({ name: "@deepseek-ai/dsh", version: "1.0.0" }));
  writeFileSync(path.join(libDir, "bin.js"), MOCK_BIN_TEMPLATE);
  writeFileSync(path.join(libDir, "plugin-hash.js"), "export function runPlugin() { return 0; }\n");
  return tmp;
}

// ─── Tests for patchDshBin / unpatchDshBin ────────────────────────

test("patchDshBin inserts hook into case plugin", () => {
  // We test the patching logic directly by replicating what patchDshBin does,
  // without importing install-gate.js (which would resolve SELF_URL to the
  // real plugin path and write into the real dsh installation).
  //
  // Instead, we test the regex-based insertion logic in isolation.

  const src = MOCK_BIN_TEMPLATE;
  const MARKER_START = "// security-review:install-gate:start";
  const MARKER_END = "// security-review:install-gate:end";

  const pluginCaseRegex = /case\s+["']plugin["']\s*:\s*\{/;
  const match = pluginCaseRegex.exec(src);
  assert.ok(match, "should find case plugin");

  const hookCode = [
    `\t\t${MARKER_START}`,
    `\t\ttry {`,
    `\t\t  const __sr = await import("file:///test/install-gate.js");`,
    `\t\t  const __srResult = await __sr.preInstallReview(invocation.profile, invocation.args);`,
    `\t\t  if (__srResult.abort) { process.stderr.write(__srResult.message + "\\n"); process.exit(__srResult.exitCode); }`,
    `\t\t} catch (__srErr) {`,
    `\t\t  process.stderr.write("error\\n");`,
    `\t\t}`,
    `\t\t${MARKER_END}`,
  ].join("\n");

  const insertPos = match.index + match[0].length;
  const patched = src.slice(0, insertPos) + "\n" + hookCode + "\n" + src.slice(insertPos);

  assert.ok(patched.includes(MARKER_START), "patched source has start marker");
  assert.ok(patched.includes(MARKER_END), "patched source has end marker");
  assert.ok(patched.includes("preInstallReview"), "patched source has hook call");
  // Original runPlugin import should still be present
  assert.ok(patched.includes('await import("./plugin-hash.js")'), "original import preserved");
});

test("patch is idempotent — re-patching removes old block first", () => {
  const MARKER_START = "// security-review:install-gate:start";
  const MARKER_END = "// security-review:install-gate:end";

  // Start with already-patched source
  const alreadyPatched = MOCK_BIN_TEMPLATE.replace(
    /case\s+["']plugin["']\s*:\s*\{/,
    `case "plugin": {\n\t\t${MARKER_START}\n\t\ttry { /* old hook */ } catch(e) {}\n\t\t${MARKER_END}`
  );

  assert.ok(alreadyPatched.includes(MARKER_START), "source has old patch");

  // Remove old patch
  const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const stripRe = new RegExp(escapeRegex(MARKER_START) + "[\\s\\S]*?" + escapeRegex(MARKER_END) + "\\n?", "g");
  let stripped = alreadyPatched.replace(stripRe, "");
  assert.ok(!stripped.includes(MARKER_START), "old patch removed");
  assert.ok(!stripped.includes(MARKER_END), "old patch removed");

  // Re-insert new patch
  const pluginCaseRegex = /case\s+["']plugin["']\s*:\s*\{/;
  const match = pluginCaseRegex.exec(stripped);
  const insertPos = match.index + match[0].length;
  const newHook = `\n\t\t${MARKER_START}\n\t\t/* new hook */\n\t\t${MARKER_END}\n`;
  const rePatched = stripped.slice(0, insertPos) + newHook + stripped.slice(insertPos);

  // Only one occurrence of each marker
  assert.equal((rePatched.match(new RegExp(escapeRegex(MARKER_START), "g")) || []).length, 1, "only one start marker");
  assert.equal((rePatched.match(new RegExp(escapeRegex(MARKER_END), "g")) || []).length, 1, "only one end marker");
});

// ─── Tests for parseAddSpecs logic ─────────────────────────────────

test("parseAddSpecs extracts package specs from pnpm add args", () => {
  // Inline the parseAddSpecs logic for testing
  function parseAddSpecs(args) {
    const addIdx = args.indexOf("add");
    if (addIdx === -1) return { specs: [], isAdd: false };
    const specs = [];
    for (let i = addIdx + 1; i < args.length; i++) {
      const arg = args[i];
      if (arg.startsWith("-")) continue;
      if (["add", "remove", "install", "update", "why"].includes(arg)) continue;
      specs.push(arg);
    }
    return { specs, isAdd: true };
  }

  // Simple add
  assert.deepEqual(parseAddSpecs(["add", "some-pkg"]), { specs: ["some-pkg"], isAdd: true });

  // Add with flags
  assert.deepEqual(parseAddSpecs(["add", "-D", "some-pkg"]), { specs: ["some-pkg"], isAdd: true });

  // Add multiple packages
  assert.deepEqual(parseAddSpecs(["add", "pkg-a", "pkg-b@1.0.0"]), { specs: ["pkg-a", "pkg-b@1.0.0"], isAdd: true });

  // Add with flags interspersed
  assert.deepEqual(parseAddSpecs(["add", "--save-dev", "pkg-a", "pkg-b"]), { specs: ["pkg-a", "pkg-b"], isAdd: true });

  // Non-add commands
  assert.deepEqual(parseAddSpecs(["remove", "some-pkg"]), { specs: [], isAdd: false });
  assert.deepEqual(parseAddSpecs(["update"]), { specs: [], isAdd: false });
  assert.deepEqual(parseAddSpecs(["why", "some-pkg"]), { specs: [], isAdd: false });
  assert.deepEqual(parseAddSpecs(["install"]), { specs: [], isAdd: false });
});

// ─── Tests for --ignore-scripts attachment ────────────────────────

test("--ignore-scripts is attached when missing and add is detected", () => {
  const args = ["add", "some-pkg"];
  let modifiedArgs = args;
  if (!args.includes("--ignore-scripts") && !args.includes("--ignore-scripts=true")) {
    modifiedArgs = [...args, "--ignore-scripts"];
  }
  assert.ok(modifiedArgs.includes("--ignore-scripts"), "ignore-scripts added");
});

test("--ignore-scripts not duplicated when already present", () => {
  const args = ["add", "some-pkg", "--ignore-scripts"];
  let modifiedArgs = args;
  if (!args.includes("--ignore-scripts") && !args.includes("--ignore-scripts=true")) {
    modifiedArgs = [...args, "--ignore-scripts"];
  }
  const count = modifiedArgs.filter((a) => a === "--ignore-scripts").length;
  assert.equal(count, 1, "only one --ignore-scripts");
});

// ─── Tests for --sr-skip escape hatch ─────────────────────────────

test("--sr-skip bypasses review entirely", async () => {
  // Import the real module to test preInstallReview with --sr-skip
  const { preInstallReview } = await import("../lib/install-gate.js");
  const result = await preInstallReview("web", ["add", "some-pkg", "--sr-skip"]);
  assert.equal(result.abort, false, "sr-skip should not abort");
  assert.ok(result.modifiedArgs, "should return modified args");
  assert.ok(!result.modifiedArgs.includes("--sr-skip"), "sr-skip should be stripped from args");
});

// ─── Tests for non-add command passthrough ────────────────────────

test("non-add commands pass through without review", async () => {
  const { preInstallReview } = await import("../lib/install-gate.js");
  const result = await preInstallReview("web", ["remove", "some-pkg"]);
  assert.equal(result.abort, false, "remove should not abort");
  assert.equal(result.modifiedArgs, undefined, "remove should not modify args");
});

test("empty args pass through", async () => {
  const { preInstallReview } = await import("../lib/install-gate.js");
  const result = await preInstallReview("web", []);
  assert.equal(result.abort, false, "empty args should not abort");
});

test("null args pass through", async () => {
  const { preInstallReview } = await import("../lib/install-gate.js");
  const result = await preInstallReview("web", null);
  assert.equal(result.abort, false, "null args should not abort");
});

// ─── Test: full patch/unpatch cycle against real install-gate ─────

test("patchDshBin + unpatchDshBin round-trip on mock dsh root", async () => {
  const { patchDshBin, unpatchDshBin, isPatched } = await import("../lib/install-gate.js");

  // Create a mock dsh root with the same structure as real dsh
  const tmp = mkdtempSync(path.join(os.tmpdir(), "dsh-mock-"));
  const libDir = path.join(tmp, "lib");
  mkdirSync(libDir, { recursive: true });
  writeFileSync(path.join(tmp, "package.json"), JSON.stringify({ name: "@deepseek-ai/dsh", version: "1.0.0" }));
  writeFileSync(path.join(libDir, "bin.js"), MOCK_BIN_TEMPLATE);

  try {
    // Before patch
    assert.equal(isPatched(tmp), false, "not patched initially");

    // Patch
    const result = patchDshBin(tmp);
    assert.ok(result.patched, "patch should succeed");
    assert.ok(result.binPath, "binPath returned");
    assert.equal(isPatched(tmp), true, "isPatched after patch");

    // Verify the patched content
    const patched = readFileSync(path.join(libDir, "bin.js"), "utf8");
    assert.ok(patched.includes("security-review:install-gate:start"), "has start marker");
    assert.ok(patched.includes("security-review:install-gate:end"), "has end marker");
    assert.ok(patched.includes("preInstallReview"), "has hook call");
    assert.ok(patched.includes('await import("./plugin-hash.js")'), "original import preserved");

    // Re-patch (idempotent)
    const result2 = patchDshBin(tmp);
    assert.ok(result2.patched, "re-patch should succeed");
    const repatched = readFileSync(path.join(libDir, "bin.js"), "utf8");
    // Count actual marker comment lines (not the marker string literals embedded
    // in the self-clean block, which are needed for the hook to self-remove).
    const markerCount = (repatched.match(/^\t+\/\/ security-review:install-gate:start/gm) || []).length;
    assert.equal(markerCount, 1, "only one start marker after re-patch");

    // Unpatch
    const unpatched = unpatchDshBin(tmp);
    assert.equal(unpatched, true, "unpatch returns true");
    assert.equal(isPatched(tmp), false, "not patched after unpatch");

    // Verify unpatched content matches original (markers removed)
    const final = readFileSync(path.join(libDir, "bin.js"), "utf8");
    assert.ok(!final.includes("security-review:install-gate"), "no markers after unpatch");
    assert.ok(final.includes('await import("./plugin-hash.js")'), "original import still present after unpatch");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test("patchDshBin returns failure for missing bin.js", async () => {
  const { patchDshBin } = await import("../lib/install-gate.js");
  const result = patchDshBin("/nonexistent/path");
  assert.equal(result.patched, false, "should fail for nonexistent path");
});

test("patchDshBin returns failure when plugin case not found", async () => {
  const { patchDshBin } = await import("../lib/install-gate.js");
  const tmp = mkdtempSync(path.join(os.tmpdir(), "dsh-mock-"));
  const libDir = path.join(tmp, "lib");
  mkdirSync(libDir, { recursive: true });
  // Write a bin.js without the plugin case
  writeFileSync(path.join(libDir, "bin.js"), 'console.log("no plugin case here");\n');
  try {
    const result = patchDshBin(tmp);
    assert.equal(result.patched, false, "should fail when plugin case not found");
    assert.ok(result.reason, "should have a reason");
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
