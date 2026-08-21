# dsh-plugin-security-review

> 📖 完整使用说明：[docs/使用说明.md](./docs/使用说明.md) ｜ English user guide: [docs/USER_GUIDE.en.md](./docs/USER_GUIDE.en.md)

面向 DeepSeek Harness（dsh）的**插件安全审查插件**：安装本插件后，再安装任何其他插件前，先对该插件的源代码做静态安全审查，识别危险代码、漏洞与供应链风险，输出安全审查报告并给出安装建议；运行期还会持续审计已安装插件，拦截并禁用危险插件。

## 工作原理（三层防线）

| 层 | 时机 | 能力 |
| --- | --- | --- |
| 1. 安装预审 | 安装前（`dsh-safe-plugin add`） | 下载源码（**不执行任何安装脚本**），静态分析后给出结论；`block` 直接拒绝安装，`warn` 需人工确认，`pass` 才转发给 `dsh plugin add --ignore-scripts` |
| 2. 运行期门禁 | dsh 启动后 | 对 profile 中所有外部插件逐一审查（带缓存）；`block` 的插件被 `loader.update(id,{disabled:true})` 禁用，并把 `disabled: true` 写入 profile 的 `cordis.patch.yml` 托管拦截块，**下次启动时其代码根本不会被 import** |
| 3. 会话内工具 | 会话进行中 | `security_review` / `security_review_status` 两个工具，可随时审查任意插件/目录并读取历史报告 |

## 安装本插件

```sh
# 方式一：经本插件自带的安全安装器（推荐）
dsh-safe-plugin add dsh-plugin-security-review

# 方式二：官方安装命令（安装后同样立即生效）
dsh plugin --profile web add dsh-plugin-security-review
```

安装后，`dsh.plugin` 会自动把本包加入 `dsh.profile.bundles` 层栈（本包声明了 `dsh.bundle`），无需手工改配置。


### 卸载

```sh
dsh plugin --profile web remove dsh-plugin-security-review
```

## 审查并安装其他插件

```sh
# 审查 + 安装（block 直接拒绝；warn 需要交互确认，CI 中用 --yes）
dsh-safe-plugin add dsh-plugin-foo
dsh-safe-plugin add ./local-plugin-dir
dsh-safe-plugin add https://github.com/me/plugin.git

# 只审查不安装（--ignore 可跳过夹具/第三方目录，可重复）
dsh-safe-plugin review dsh-plugin-foo
dsh-safe-plugin review ./local-plugin-dir --json
dsh-safe-plugin review . --ignore test/fixtures --ignore dist

# 查看历史报告 / 复审已安装插件
dsh-safe-plugin list
dsh-safe-plugin verify
```

## 报告与结论

- 每份报告：安全评分（0-100）、`pass / warn / block / audit` 结论、逐条发现（级别、类别、文件:行、代码片段、建议）、安装建议与推荐命令。
- 报告持久化在 `$DSH_HOME/security-review/`：`reports/latest/<包名>.md` 为最新 Markdown 报告，`reports/history/` 为 JSON 历史，`index.json` 为索引。
- Web GUI：
  - 设置页左侧栏新增「**插件安全审查**」模块：展示当前全部已加载插件（官方内置插件灰显、无需审查），每个插件带彩色风险圆点（🟢安全 / 🟡有风险 / 🔴危险）与一句话风险提炼；「一键安全审查」按钮对全部插件执行完整静态审查；非官方插件提供「卸载」按钮（走 pnpm remove，重启后完全生效）。
  - 设置页「security-review」配置区可调审查策略（`standard / strict / audit-only`）、自动禁用开关、allowlist、installGate。

## 审查策略（settings → security-review）

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `policy` | `standard` | `standard`：critical→block；`strict`：high 也 block；`audit-only`：只记录不拦截 |
| `autoDisable` | `false` | **默认只报告不自动禁用**（稳定性优先：防止误伤合法插件或在运行中卸载服务导致 dsh 崩溃）；显式开启后，审计发现 block 才会禁用该插件 |
| `autoPatchProfile` | `false` | 默认不写 profile `cordis.patch.yml` 托管块；显式开启后，被拦截插件下次启动不再加载其代码 |
| `installGate` | `false` | **方案 B 改良版**：开启后只在缺失/失效时注入（不反复重写）、原子写入 + node --check 语法自检（失败即回滚）、插件不可用时自清理、另有 `dsh-safe-plugin install-gate/uninstall-gate` 手动管理。默认关闭，安装预审推荐 `dsh-safe-plugin add` |
| `allowlist` | `[]` | 豁免名单（包名，`*` 表示全部豁免） |

## 审查规则（节选，见 docs/design.md 与 lib/analyzer/rules.js）

- **critical**：安装生命周期脚本（preinstall/install/postinstall）、curl|wget 下载后管道执行、child_process 动态拼接/shell:true、eval/new Function 动态执行、远程动态 import、凭据+联网外传、硬编码 API key/Webhook、tarball 完整性校验失败。
- **high**：任何 child_process 调用、原生二进制（.node/.exe/.dll）、node-gyp 构建、原型污染、混淆特征（atob/fromCharCode/长 base64）、ctx.loader 控制面、包名近似知名包（typosquat）、可疑依赖。
- **medium/low**：明文 HTTP、包目录外文件写入、rm -rf、挖矿地址、缺 license/仓库/作者、压缩无源码等。

## 已知限制（诚实声明）

1. 静态分析无法覆盖原生二进制、动态下载的代码与高度混淆的载荷；block 结论是「存在强风险信号」，不是「证明恶意」。
2. 运行期门禁在本插件自身 `apply` 之后的插件 import 才有**确定性**拦截能力；同批次更早启动的插件在首次启动的毫秒级窗口内会先加载，随后被启动审计禁用，并被托管块保证下次启动不再加载。要获得确定性的安装前拦截，请使用 `dsh-safe-plugin add`。
3. 若某个被拦截插件是其他插件 `inject` 的服务提供方，禁用后启动会因缺服务而失败（这是 dsh 的 fail-loud 契约），报告会指出缺哪个服务。
4. 传递依赖（插件声明的第三方依赖）不在逐文件扫描范围内，只做名称层面的可疑检测；供应链深水区建议配合 lockfile 审计与 registry 信誉。
5. 本插件自身把「审查器运行失败」降级为 `warn`（fail-open），避免审查器自身故障瘫痪整个 dsh；可用 `dsh-safe-plugin verify` 手动复查。

## 目录结构

```
lib/
  index.js            宿主插件（settings 区、agent 工具、启动审计、事件）
  gate.js             运行期 import 门禁（EntryTree.prototype.import 补丁 + 作用域判定）
  store.js            报告/缓存持久化（$DSH_HOME/security-review）
  patch-manager.js    profile cordis.patch.yml 托管拦截块
  settings.js         设置区 schema 与接线
  tools.js            security_review / security_review_status 工具
  cli/index.js        dsh-safe-plugin CLI（安装预审主入口）
  analyzer/           纯静态分析器（零依赖，CLI 与宿主共用）
    rules.js          规则引擎（18 组规则）
    score.js          评分、结论与策略
    tar.js            tar.gz 解包（防路径穿越/zip bomb）
    registry.js       registry 元数据/版本选择/tarball 完整性校验
    semver.js         极简 semver
    known.js          知名包名清单（typosquat 比对）
    render.js         Markdown 报告渲染
test/                 node --test 单元测试与恶意/良性夹具
```
## 从本地源码安装（开发/内网场景）

```sh
# 先把本仓库链接进 profile（link: 不需要发布到 registry）
dsh plugin --profile web add link:D:/Coding/安全审查插件

# CLI 的三种调用方式（任选其一）：
# 1) 全局安装（把 bin 放进 PATH，之后可直接用 dsh-safe-plugin）
npm i -g D:/Coding/安全审查插件
# 2) 用 profile 内生成的 bin（pnpm 会自动为带 bin 的依赖建 shim）
& "$env:USERPROFILE.dshprofilesweb
ode_modules.bindsh-safe-plugin.cmd" --help
# 3) 直接以 node 运行
node "D:/Coding/安全审查插件/lib/cli/index.js" review ./某个插件目录

# 运行单元测试（不需要 dsh 环境，零依赖；注意不要在 test 后加反斜杠）
cd D:/Coding/安全审查插件
node --test test

# 对本插件自身做一次自审（排除刻意构造的恶意测试夹具后应为 warn 而非 block）
node lib/cli/index.js review . --ignore test/fixtures
```

