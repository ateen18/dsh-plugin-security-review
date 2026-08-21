# 安全审查插件 install-gate 引入启动崩溃修复报告

- **文档生成时间**：2026-08-20（GMT+8）
- **影响范围**：dsh 无法启动（插件模块图加载即崩溃）
- **状态**：✅ 已修复，测试套件 37/37 通过
- **关联提交**：`836d75e feat: add install-gate and install watcher, fix boot-crash SyntaxError`

---

## 一、背景

本插件在 2026-08-20 的评估与改进（见 `2026-08-20-插件评估与改进报告.md`）之后，又新增了 install-gate（改写 dsh `lib/bin.js` 注入安装预审钩子）与 install watcher（监听 profile `package.json` 变化）两个模块，并对 `index.js`、`gate.js`、`settings.js` 等做了配套调整。这些改动尚未提交时，用户重启 dsh 发现**又一次无法启动**。

本次排查定位到四重缺陷叠加，其中第一项为阻断性根因，直接导致插件模块无法解析；后三项是 install-gate 模块自身的潜伏 bug，在该模块因默认关闭而从未真正执行时一直未暴露。

---

## 二、问题清单

### 问题 1（根因，阻断性）：`lib/index.js` 重复声明导致 SyntaxError

**现象**：dsh 启动崩溃，插件树加载失败。

对 `lib/index.js` 执行语法检查：

```
$ node --check lib/index.js
<插件源码目录>\lib\index.js:98
  const store = new ReviewStore();
        ^
SyntaxError: Identifier 'store' has already been declared
```

**根因分析**：

在新增 install-gate 的 try-catch 块时，`apply()` 顶层的初始化声明被误粘贴了两次。第一组位于第 65-69 行，第二组位于 install-gate try-catch 之后的第 98-102 行：

```js
export async function apply(ctx, config = {}) {
  try {                          // 外层兜底 try
    ...
    const store = new ReviewStore();          // 第 65 行（原始）
    const managedPatch = ...                  // 第 66 行（原始）
    let policy = normalizePolicy(config);     // 第 68 行（原始）
    const policyNow = () => policy;           // 第 69 行（原始）

    try { ... install-gate 处理 ... }         // 第 77-97 行（新增的嵌套 try-catch）

    const store = new ReviewStore();          // 第 98 行（误粘贴的重复声明）
    const managedPatch = ...                  // 第 99 行（重复）
    let policy = normalizePolicy(config);     // 第 101 行（重复）
    const policyNow = () => policy;           // 第 102 行（重复）
```

第二组与第一组处于同一函数作用域（install-gate 的 try-catch 是嵌套块，不影响外层作用域），`const` / `let` 在同一作用域重复声明会在模块解析阶段抛 `SyntaxError`。由于该错误发生在 `import` 求值之前，整个插件模块无法加载，dsh 的 fail-loud 契约下即表现为启动失败。

这与 2026-08-18 的启动崩溃（顶层静态导入宿主包导致 `ERR_MODULE_NOT_FOUND`）症状相同、根因不同——上一次是"模块找不到"，这一次是"模块自身语法不合法"。

**解决措施**：删除第 98-102 行的重复声明，保留第 65-69 行的原始声明。install-gate 的 try-catch 块本身不动，其中引用的 `policy`、`dshInstallRoot` 均指向原始声明。

---

### 问题 2：`lib/install-gate.js` 钩子代码双重引号

**现象**：install-gate 默认关闭，故此前从未触发；本次专门测试 patch/unpatch 往返时发现 `patchDshBin` 生成的 `bin.js` 始终无法通过语法自检。

**根因分析**：

`buildHookCode()` 第 66 行原为：

```js
`\t\t  const __sr = await import("${JSON.stringify(SELF_URL)}");`,
```

`JSON.stringify(SELF_URL)` 的返回值本身已带一对双引号（如 `"file:///D:/.../install-gate.js"`），而模板字面量里又在外层包了一对 `"..."`，生成的代码变成：

```js
const __sr = await import(""file:///D:/.../install-gate.js"");
```

`node --check` 因此报 `Unexpected identifier`。`writeBinAtomically` 写入临时文件后语法自检失败，`patchDshBin` 返回 `{ patched: false, reason: "syntax check failed: ..." }`，install-gate 功能实际不可用。

**解决措施**：移除多余的外层引号，由 `JSON.stringify` 提供合法字符串字面量：

```js
`\t\t  const __sr = await import(${JSON.stringify(SELF_URL)});`,
```

---

### 问题 3：`lib/install-gate.js` 剥离正则被自清理字面量误导

**现象**：修复问题 2 后 patch 成功，但 `unpatchDshBin` 始终返回 `false`，patch/unpatch 往返测试失败。

**根因分析**：

install-gate 注入的钩子块内含一段**自清理逻辑**——当插件被卸载/移动导致 `import` 失败时，钩子在 catch 块里自行从 `bin.js` 剥离自身。该逻辑运行时无法 import 本模块取常量，因此把 marker 字符串硬编码为字面量：

```js
const __s2 = "// security-review:install-gate:start";
const __e2 = "// security-review:install-gate:end";
```

于是 patched 文件中 `security-review:install-gate:start` 出现两次：一次是真正的注释 marker，一次是自清理块里的字符串字面量；`end` 同理。文件结构为：

```
// security-review:install-gate:start        ← 真实 start marker
  try { ... 钩子逻辑 ...
    const __s2 = "...install-gate:start";   ← 自清理字面量
    const __e2 = "...install-gate:end";     ← 自清理字面量（出现在真实 end 之前）
  } catch {}
// security-review:install-gate:end          ← 真实 end marker
```

`stripExistingPatch` 原剥离正则为朴素子串匹配、非贪婪：

```js
new RegExp(escapeRegex(MARKER_START) + "[\\s\\S]*?" + escapeRegex(MARKER_END) + "\\n?", "g")
```

非贪婪匹配从真实 start marker 出发，遇到**第一个** `end` 子串即停止——而那正是自清理块里的 `__e2` 字面量（它排在真实 end marker 之前）。结果是只剥掉了从真实 start 到自清理 `__e2` 之间的片段，留下后半段悬空代码，`node --check` 失败，`unpatchDshBin` 返回 `false`。

**解决措施**：把 marker 锚定到行首，只匹配作为注释行出现的 marker，不匹配字符串字面量：

```js
new RegExp(
  "^[ \\t]*" + escapeRegex(MARKER_START) + "[\\s\\S]*?" +
  "^[ \\t]*" + escapeRegex(MARKER_END) + "\\n?",
  "gm"
)
```

`^[ \t]*` 要求 marker 出现在行首（仅前置空白），自清理块里的字面量位于 `const __s2 = "..."` 赋值语句中、不在行首，故不被匹配。这样非贪婪匹配会正确跨越自清理块、终止于真实 end marker，整块剥离。

---

### 问题 4：`test/install-gate.test.mjs` marker 计数断言同步缺陷

**现象**：修复问题 2 后，"re-patch 幂等"断言报 `2 !== 1`。

**根因分析**：与问题 3 同源。测试用朴素子串匹配计数 marker：

```js
const markerCount = (repatched.match(/security-review:install-gate:start/g) || []).length;
assert.equal(markerCount, 1, "only one start marker after re-patch");
```

该正则把自清理块里的字符串字面量也数了进去，期望 1、实际 2。幂等逻辑本身正确（第二次 patch 返回 `written: false`，未重写），是计数方式有缺陷。

**解决措施**：改为行首锚定、只数注释 marker 行：

```js
const markerCount = (repatched.match(/^\t+\/\/ security-review:install-gate:start/gm) || []).length;
```

---

## 三、变更文件清单

本次会话实际改动（问题修复）涉及 3 个文件。提交 `836d75e` 同时包含了此前未提交的 install-gate / watcher 功能新增与配套调整，合计 21 个文件。

| 文件 | 变更类型 | 说明 |
|---|---|---|
| `lib/index.js` | 修改 | 删除 `apply()` 中 install-gate try-catch 之后的 4 行重复声明（`store` / `managedPatch` / `policy` / `policyNow`），恢复模块可加载 |
| `lib/install-gate.js` | 修改 | `buildHookCode` 移除 `import()` 参数多余外层引号；`stripExistingPatch` 剥离正则改为行首锚定，区分注释 marker 与自清理字面量 |
| `test/install-gate.test.mjs` | 修改 | marker 计数正则改为行首锚定，只数注释 marker 行 |

---

## 四、验证结果

| # | 验证项 | 结果 |
|---|---|---|
| 1 | `node --check lib/index.js`（原报错点） | ✅ PASS |
| 2 | `node --check` 全部 lib 文件（含 analyzer / cli） | ✅ PASS |
| 3 | `patchDshBin` + `unpatchDshBin` 往返（mock dsh root） | ✅ PASS（patch 成功、幂等、unpatch 还原） |
| 4 | 模块图加载测试 `startup.test.mjs`（"plugin module graph loads"） | ✅ PASS——dsh 能否加载插件的关键测试 |
| 5 | 完整测试套件 `npm test*.test.mjs` | ✅ 37/37 通过，0 失败 |

---

## 五、遗留事项与建议

1. **install-gate 仍默认关闭**：改写全局 dsh `lib/bin.js` 属高危操作，默认 `installGate: false` 是稳定性取舍。安装期预审继续推荐独立 CLI `dsh-safe-plugin add`。如需让原生 `dsh plugin add` 也走审查，可在设置中显式开启，并知晓 dsh 升级覆盖 `bin.js` 后需重新注入（本插件已实现低频重注入与自清理）。

2. **自清理字面量与正则的耦合**：问题 3 的根因是"marker 字符串既作注释标记、又作自清理字面量"这一设计。当前用行首锚定规避，能正确区分两者；若日后 marker 格式变化（例如改用块注释或多行 marker），需同步检查 `stripExistingPatch` 与测试正则是否仍能区分。更稳妥的长期做法是让自清理块使用与 marker 注释不同的、不可混淆的字面量。

3. **真实启动确认**：测试套件验证了模块图可加载与 install-gate 逻辑正确性，但 dsh 端到端启动涉及 profile 组合与宿主包解析，建议在本机执行 `npx @deepseek-ai/dsh web` 做最终确认。

---

*报告人：WorkBuddy（AI 助手）　生成于 2026-08-20 GMT+8*