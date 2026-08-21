import { spawnSync } from "node:child_process";
import { globSync } from "node:fs";

/**
 * 全量语法校验：对 lib 与 scripts 下所有 .js 执行 node --check（真实 ESM 解析器）。
 * 能抓住手写 bundle/正则编辑时的缺括号、缺逗号等静态校验盲区。
 */
const files = [...globSync("lib/**/*.js"), ...globSync("scripts/**/*.js")];
let bad = 0;
for (const file of files) {
  const result = spawnSync(process.execPath, ["--check", file], { encoding: "utf8" });
  if (result.status !== 0 || result.error) {
    bad += 1;
    console.error("❌", file);
    console.error((result.stderr || result.error?.message || "").split("\n").slice(0, 8).join("\n"));
  }
}
if (bad === 0) {
  console.log("✅ 全部 " + files.length + " 个文件语法校验通过");
  process.exit(0);
}
console.error(bad + " 个文件语法错误");
process.exit(1);
