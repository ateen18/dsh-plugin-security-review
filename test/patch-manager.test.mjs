import path from "node:path";
import os from "node:os";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import { ManagedPatch, MANAGED_BEGIN, MANAGED_END } from "../lib/patch-manager.js";

function tempProfile(initial) {
  const dir = mkdtempSync(path.join(os.tmpdir(), "dsh-pm-test-"));
  if (initial !== undefined) writeFileSync(path.join(dir, "cordis.patch.yml"), initial, "utf8");
  return dir;
}

test("managed block writes and reads ids", () => {
  const dir = tempProfile("# comment\n- id: user-entry\n  disabled: true\n");
  const mp = new ManagedPatch(dir);
  mp.sync(["plugin-b", "plugin-a"]);
  const text = readFileSync(mp.file, "utf8");
  assert.ok(text.includes("# comment"), "user content preserved");
  assert.ok(text.indexOf("plugin-a") < text.indexOf("plugin-b"), "ids sorted");
  assert.deepEqual(mp.managedIds(), ["plugin-a", "plugin-b"]);
  rmSync(dir, { recursive: true, force: true });
});

test("emptying the block keeps the file a valid top-level YAML array", () => {
  // 回归：清空 managed block 后文件若只剩注释，YAML 解析为 null，
  // dsh 启动抛 "must be a top-level YAML array"
  const dir = tempProfile("# header comment\n" + MANAGED_BEGIN + "\n- id: \"x\"\n  disabled: true\n" + MANAGED_END + "\n");
  const mp = new ManagedPatch(dir);
  mp.sync([]);
  const text = readFileSync(mp.file, "utf8");
  const contentLines = text.split(/\r?\n/).filter((l) => {
    const t = l.trim();
    return t !== "" && !t.startsWith("#");
  });
  assert.ok(contentLines.length > 0, "file still has array content, not only comments");
  assert.equal(contentLines[0].trim(), "[]", "empty array placeholder present");
  rmSync(dir, { recursive: true, force: true });
});

test("comments-only file with fresh block also gets array placeholder", () => {
  const dir = tempProfile("# only comments here\n");
  const mp = new ManagedPatch(dir);
  mp.sync([]);
  const text = readFileSync(mp.file, "utf8");
  assert.ok(text.trim().startsWith("[]"), "starts with empty array");
  rmSync(dir, { recursive: true, force: true });
});

test("sync(ids) after sync([]) removes the [] placeholder", () => {
  // 回归：sync([]) 写入 "[]" 占位行，后续 sync(["a"]) 保留了 "[]" 行，
  // 导致 YAML 顶层是空数组后跟 - id 条目——非法 YAML，dsh 解析崩溃。
  const dir = tempProfile("# header\n");
  const mp = new ManagedPatch(dir);
  mp.sync([]);
  let text = readFileSync(mp.file, "utf8");
  assert.ok(text.includes("[]"), "placeholder written after sync([])");

  mp.sync(["a", "b"]);
  text = readFileSync(mp.file, "utf8");
  assert.ok(!text.includes("[]"), "[] placeholder removed when entries exist");
  assert.deepEqual(mp.managedIds(), ["a", "b"]);

  // 再清空 → [] 回来
  mp.sync([]);
  text = readFileSync(mp.file, "utf8");
  assert.ok(text.includes("[]"), "placeholder restored after sync([])");

  // 再加条目 → [] 消失
  mp.sync(["c"]);
  text = readFileSync(mp.file, "utf8");
  assert.ok(!text.includes("[]"), "placeholder removed again");
  assert.deepEqual(mp.managedIds(), ["c"]);

  rmSync(dir, { recursive: true, force: true });
});
