# 设计文档：dsh-plugin-security-review

## 1. 威胁模型

dsh 插件与普通 npm 包不同：它在**宿主进程**内以完整权限运行（可读 `$DSH_HOME` 的会话、凭据与设置，可调用 `ctx.loader` 装卸其他插件），客户端半边则在**浏览器页面**内运行。因此一个恶意插件可以：

- 安装时通过 `preinstall/install/postinstall` 脚本直接执行任意命令（这是安装期最大的攻击面）；
- 加载时通过模块顶层代码窃取环境变量/凭据/会话并外传；
- 运行期通过 `ctx.loader` 禁用安全插件、篡改配置、注册恶意工具诱骗模型执行危险操作。

本插件把「审查」放在三个时间点上，对应三个攻击面：**安装前（CLI 预审）**、**import 前（运行期门禁）**、**会话中（审计 + 工具）**。

## 2. dsh 加载机制的关键事实（决定门禁形态）

（以下结论来自对 dsh 0.1.0-rc.6 源码的核对：`dsh-app-boot`、`@deepseek-ai/cordis-plugin-loader`、`dsh` CLI。）

1. profile 的组成是一个扁平补丁列表：每个 bundle 的 `cordis.patch.yml`（按 `dsh.profile.bundles` 顺序）→ profile 自身 `cordis.patch.yml` → `$DSH_HOME/cordis.patch.yml` → `--patch` 覆盖层。`composeEntries` 把所有层拍平成一张 entry 列表，作为**一次** `EntryGroup.update` 应用。
2. `EntryGroup.update` 在一个同步循环里为每个 entry 依次发出 `tree.import(name)` 请求（`Promise.allSettled(config.map(create))` 的同步前缀），**所有 import 请求在任何一个插件模块的顶层代码执行之前就已经全部发出**。
3. 因此：任何「作为 profile 插件加载」的代码，都无法在同一批次的 import 请求发出前安装钩子 —— 包括把自己放在 bundle 列表第一位。loader 只提供 `loader/entry-init`（Entry 构造时、options 尚未挂上）等事件，没有「import 前可 await」的批前钩子。
4. `dsh plugin add` 是 pnpm 的薄转发器，没有任何第三方可挂的安装前钩子；pnpmfile 也无法拿到源码做静态审查。
5. loader 的写回（`EntryTree.write`）会把组合后的树（含 `disabled: true`）写进 profile 的 `cordis.yml`，但 `prepareProfile` 每次启动都会把它重置为空列表 —— 所以「禁用状态」不能依赖该文件持久化，必须写在 profile 的 `cordis.patch.yml` 补丁层。

**结论**：确定性最强的拦截点在安装流程（CLI 预审）；运行期门禁对「本插件 apply 之后的 import」是确定性的（补丁 `EntryTree.prototype.import`），对同批次更早启动的插件只能做「启动后毫秒级审计 + 禁用 + 托管补丁块保下次」；两者叠加后，恶意插件在第二次启动起就完全无法加载。

## 3. 组件

### 3.1 纯静态分析器（lib/analyzer，零依赖）

- `collectFiles`：带上限（5000 文件 / 单文件 2MB / 总量 200MB / 深度 24）的递归收集，跳过 `node_modules/.git`，二进制扩展名单独登记。
- `extractTgz`：自实现 ustar + GNU longname + PAX 解包器；路径穿越拒绝、符号链接只记录不创建、总量/文件数上限，防 zip bomb。
- `resolveRegistrySpec/downloadTarball`：registry 元数据 + 极简 semver 选版本 + tarball 下载，**sha512/sha1 完整性校验**，校验失败即产生 critical 发现。
- `runRules`：18 组规则（见 rules.js 注释），按文件/包两级运行，每规则每文件封顶 6 条、总封顶 300 条。
- `scoreFindings + verdictFor`：critical 计 55 分扣减（前 2 个）、high 18、medium 4（封顶 6 条）、low 1；`standard` 下 critical→block、评分<30→block、high→warn、评分<60→warn；`strict` 下 high→block；`audit-only` 不拦截。allowlist 豁免。
- `renderReportMarkdown`：中文 Markdown 报告。

### 3.2 安装预审 CLI（lib/cli/index.js，bin: dsh-safe-plugin）

- `add <spec>`：reviewSpec → 输出报告 → block 且无 `--force` 时退出码 2 拒绝安装；warn 无 `--yes` 时交互确认（非 TTY 拒绝并要求 `--yes`）；通过后执行 `dsh plugin --profile <p> add <spec> --ignore-scripts`（安装脚本不执行）；安装完成后对真实落盘内容**复审**，并持久化报告。
- `review <spec>`：只审查，输出报告（`--json` 可机器读）。
- `list` / `verify [name]`：历史报告与已安装插件复审。

### 3.3 运行期门禁（lib/gate.js + lib/index.js）

- `apply` 时把 `gateState` 接上（store/policy/profileDir/dsh 安装根），并 `installImportGate()`：一次性补丁 `EntryTree.prototype.import`，此后任何 loader 驱动的插件 import（HMR 重载、动态挂载）都先经过 `gateBeforeImport`。
- `gateBeforeImport`：解析 specifier → 定位包目录 → 作用域判定（`packageDir` 在 profile 下、或声明了 `dsh.*` 且不在 dsh 安装目录内、且不是本插件自身）→ 查缓存/现场分析 → block 时抛 `SECURITY_REVIEW_BLOCKED`（该 entry 导入失败，loader 报错包含结论与报告路径；不执行任何插件代码）。
- 启动审计：`loader.await()` 稳定后遍历 `loader.entries()`，对每个作用域内插件 `decideFor`；block → `loader.update(id,{disabled:true})` 禁用 + `ManagedPatch.sync()` 把 `- id: x / disabled: true` 写进 profile `cordis.patch.yml` 的托管块（行式编辑，不破坏用户其余内容）。下次启动这些行在组合阶段就生效，插件**不会被 import**。
- 事件：`security-review/report`、`security-review/blocked`、`security-review/complete`（供未来客户端 UI 或会话投影消费）。

### 3.4 会话内工具（lib/tools.js）

- `security_review(target, fresh?)`：审查本地目录/npm 包/git/tgz，返回完整报告 + Markdown + 安装建议。
- `security_review_status()`：已安装插件审查状态总览。

### 3.5 设置区（lib/settings.js）

- namespace `security-review`：`policy`（standard/strict/audit-only）、`autoDisable`、`autoPatchProfile`、`allowlist`。通过 `installSettingsSection` 接线，web 设置页即可编辑；策略变化会触发重新审计。

## 4. 缓存与持久化

- `$DSH_HOME/security-review/cache/<包名>-<sha1(name|version|文件数|最新mtime)>.json`：判定缓存，重建（不升版本号）也会失效。
- `reports/latest/<包名>.md`、`reports/history/*.json`、`index.json`。
- profile `cordis.patch.yml` 托管块（MARKER 注释包裹，自动增删行）。

## 5. 明确的取舍

- 审查器失败降级为 warn（fail-open）：可用性优先，配合 `verify` 手动复查；被托管块拦住的插件不受此影响（块是持久化的）。
- 不拦截 dsh 自带插件（安装目录内），不拦截本插件自身；只审计 profile 侧的外部插件行。
- 不自动删除/卸载任何插件：只禁用 + 报告，把最终处置权留给用户。
- 传递依赖不逐文件扫描（成本），只做包名近似/可疑源检测。
