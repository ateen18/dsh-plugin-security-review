import path from "node:path";
import os from "node:os";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import { startInstallWatcher, readProfileDeps } from "../lib/watcher.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function tempProfile(initial) {
  const dir = mkdtempSync(path.join(os.tmpdir(), "dsh-watcher-test-"));
  if (initial !== undefined) writeFileSync(path.join(dir, "package.json"), initial, "utf8");
  return dir;
}

test("readProfileDeps returns {} when no package.json", () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "dsh-wp-test-"));
  assert.deepEqual(readProfileDeps(dir), {});
  rmSync(dir, { recursive: true, force: true });
});

test("install watcher fires on added dependencies", async () => {
  const dir = tempProfile('{"dependencies":{"a":"1.0.0"}}');
  const events = [];
  const w = startInstallWatcher({
    profileDir: dir,
    debounceMs: 30,
    pollMs: 80,
    onChanged: (e) => events.push(e)
  });
  await sleep(120);
  writeFileSync(path.join(dir, "package.json"), '{"dependencies":{"a":"1.0.0","b":"2.0.0"}}', "utf8");
  await sleep(350);
  w.close();
  const added = events.flatMap((e) => e.added);
  assert.ok(added.includes("b"), "new dependency 'b' detected, got: " + JSON.stringify(events));
  rmSync(dir, { recursive: true, force: true });
});

test("install watcher detects version changes and removals", async () => {
  const dir = tempProfile('{"dependencies":{"a":"1.0.0","c":"3.0.0"}}');
  const events = [];
  const w = startInstallWatcher({
    profileDir: dir,
    debounceMs: 30,
    pollMs: 60,
    onChanged: (e) => events.push(e)
  });
  await sleep(100);
  writeFileSync(path.join(dir, "package.json"), '{"dependencies":{"a":"2.0.0"}}', "utf8");
  await sleep(350);
  w.close();
  const flat = events.flatMap((e) => e.changed).concat(events.flatMap((e) => e.removed));
  assert.ok(flat.includes("a"), "version change on 'a' detected");
  assert.ok(flat.includes("c"), "removal of 'c' detected");
  rmSync(dir, { recursive: true, force: true });
});

test("watcher closes cleanly and stops firing", async () => {
  const dir = tempProfile('{"dependencies":{"x":"1.0.0"}}');
  const events = [];
  const w = startInstallWatcher({
    profileDir: dir,
    debounceMs: 20,
    pollMs: 50,
    onChanged: (e) => events.push(e)
  });
  w.close();
  await sleep(100);
  writeFileSync(path.join(dir, "package.json"), '{"dependencies":{"x":"1.0.0","y":"2.0.0"}}', "utf8");
  await sleep(200);
  assert.equal(events.length, 0, "no events after close");
  rmSync(dir, { recursive: true, force: true });
});

test("watcher with null profileDir is a no-op", () => {
  const w = startInstallWatcher({ profileDir: null, onChanged: () => {} });
  assert.doesNotThrow(() => w.close());
});
