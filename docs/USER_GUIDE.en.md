# dsh-plugin-security-review — User Guide

A security review plugin for DeepSeek Harness (dsh). Once installed, every other plugin is statically reviewed **before it is installed or loaded** (dangerous code, vulnerabilities, supply-chain risks), and installed plugins are continuously audited at runtime, with reports and install recommendations produced.

**Version**: 0.1.0 (MIT)　**Repository**: https://github.com/ateen18/dsh-plugin-security-review

---

## 1. Feature Overview

| Entry | Capabilities |
| --- | --- |
| **CLI: `dsh-safe-plugin`** | Pre-install review (review → verdict → block/allow, then forward install); review-only; history; re-review installed plugins; manual install-gate management |
| **Web settings page: “Plugin Security Review”** | Full plugin roster (official built-ins shown grey, exempt); one-click review; risk-grouped collapsible list (danger/risk expanded, safe collapsed); color dots; verdict-aligned human-readable risk summary; one-click uninstall; error retry |
| **In-session tools** | `security_review` (review any target), `security_review_status` (installed-plugin status) |
| **Runtime gate** | Full audit after boot (cached); plugins mounted later are intercepted before import (block is replaced with a no-op module, their code never runs); when `dshInstallRoot` cannot be resolved the review scope narrows to profile-local packages and unknown targets pass through |

## 2. Installation

### 2.1 Install this plugin

```sh
# Option 1: npm registry
dsh plugin --profile web add dsh-plugin-security-review

# Option 2: GitHub (no npm publish needed; the repo is cloned automatically)
dsh plugin --profile web add github:ateen18/dsh-plugin-security-review

# Option 3: local development (link: — changes take effect immediately)
dsh plugin --profile web add link:<your-plugin-source-dir>

# Option 4: safe installer (self-review first; requires the CLI, see 2.2)
dsh-safe-plugin add dsh-plugin-security-review
```

> **Dependencies**: the `@deepseek-ai/*` packages (cordis-plugin-loader / dsh-settings / dsh-tools / schemastery) are **optionalDependencies** — if the registry cannot resolve them the install still succeeds; at runtime the host's own copies are resolved from the dsh installation directory (single module instance), and profile-local copies are only a fallback.

### 2.2 Making the CLI available

```sh
# ① Global install (bin lands on PATH)
npm i -g dsh-plugin-security-review

# ② Use the bin shim pnpm created inside the profile
& "$env:USERPROFILE\.dsh\profiles\web\node_modules\.bin\dsh-safe-plugin.cmd" --help

# ③ Run with node directly
node "<your-plugin-source-dir>/lib/cli/index.js" --help
```

### 2.3 Uninstall this plugin

```sh
dsh plugin --profile web remove dsh-plugin-security-review
```

## 3. Pre-install Review of Other Plugins (recommended workflow)

```sh
# Review + install:
#   pass  → proceed (auto-appends --ignore-scripts; lifecycle scripts never run)
#   warn  → interactive [y/N] (use --yes in CI)
#   block → install refused (exit 2; --force overrides at your own risk)
dsh-safe-plugin add dsh-plugin-foo
dsh-safe-plugin add ./local-plugin-dir
dsh-safe-plugin add https://github.com/me/plugin.git

# Review only (--json for machine-readable output; --ignore <pattern> to skip dirs)
dsh-safe-plugin review dsh-plugin-foo
dsh-safe-plugin review . --ignore test/fixtures

# History / re-review installed plugins
dsh-safe-plugin list
dsh-safe-plugin verify [package]
```

![Terminal pre-install review (report)](images/terminal-review-1.png)

![Terminal pre-install review (verdict & recommendation)](images/terminal-review-2.png)

> Note: plain `dsh plugin add` does **not** go through pre-review by default (`installGate` is off to avoid rewriting global dsh files); see §7 if you want native installs reviewed too.

## 4. Web Settings Page: Plugin Security Review

Path: **Settings → sidebar “Plugin Security Review”**.

### 4.1 UI overview

- **One-click security review**: runs a full static review of every loaded plugin (cached; repeated clicks are instant; shows “Reviewing…” while running);
- **Review / Install tools** (GUI replacement for the terminal CLI):
  - Enter a target (package name / local dir / git URL / .tgz URL) → “Review”: runs the review and shows verdict, score and risk summary;
  - “Safe install”: reviews first; `pass` installs directly (auto `--ignore-scripts`), `warn`/`block` shows the risks plus a “confirm and force install” button; prompts restart after install;
  - **install-gate toggle**: one-click enable/disable “native `dsh plugin add` also goes through pre-review” (high-risk, off by default, double-confirmed before switching).
- **Grouped list** (empty groups are not rendered):
  - 🔴 **Dangerous plugins** (block): shown expanded, with an uninstall button;
  - 🟡 **Risky plugins** (warn): shown expanded, with an uninstall button;
  - 🟢 **Safe plugins** (pass/audit/built-in/not-reviewed): collapsed by default; click “▸ Expand” to view, “▾ Collapse” to hide;
- **Each row**: color dot (🟢 safe / 🟡 risky / 🔴 dangerous / grey = built-in or not reviewed) + package name and version + one-line human-readable risk summary + uninstall button;
- **Uninstall**: non-official plugins only; `confirm` dialog → removed from profile dependencies (`pnpm remove`) → “takes full effect after restart”;
- **Retry**: when a request fails, the error and a “Retry” button are shown (e.g. host API not registered yet).

> Official built-in plugins are greyed out as “built-in”, exempt from review and uninstall.

![Web settings: Plugin Security Review (with review/install tools panel)](images/web-review.png)

### 4.2 How the risk summary relates to the verdict (important)

The summary is **aligned with the verdict**:

| Verdict | Example summary |
| --- | --- |
| Safe (pass) | `Safe (score 92)`; with medium/low notes: `Safe (score 89) (3 medium/low notes, see report)` — **no risk words listed** |
| Risky (warn) | `Risky (score 46) — browser-side data leak, dynamic/obfuscated code execution` (only critical/high) |
| Dangerous (block) | `Dangerous (score 30) — hardcoded keys (API key leak), credential/data exfiltration` |
| Audit / Built-in / Not reviewed | `Audit only (score X)` / `dsh built-in plugin, no review needed` / `Not reviewed yet — click the review button above` |

In short: **“Safe” = no high-severity signal, not “zero findings”**; medium/low notes are folded into the parenthetical, full details live in the Markdown report.

## 5. In-session Tools

The model can call these tools during a session:

- **`security_review(target, fresh?)`**: review a local directory / npm package (with optional @version) / git URL / tgz URL; returns the full report (score, per-finding detail, verdict, install recommendation) plus Markdown;
- **`security_review_status(profile?, fresh?)`**: overview of installed plugins in the current profile (verdict/score/finding count/blocked).

## 6. Reports and Verdicts

### Report storage

```text
$DSH_HOME/security-review/
├── cache/                  # review cache (keyed by package identity + rules version, auto-invalidates)
├── reports/latest/<name>.md      # latest Markdown report
├── reports/history/              # JSON history
└── index.json                    # index
```

### Verdicts and scoring

| verdict | Meaning | Action |
| --- | --- | --- |
| `pass` | No high-severity findings | Can install (still recommended to skip install scripts) |
| `warn` | High-severity findings need human review | Install with caution |
| `block` | Strong critical/high risk signals | Do not install / consider uninstalling |
| `audit` | Audit-only mode | Record only, never block |

Score 0–100; `standard` policy: any critical → block, score <30 → block, any high → warn, score <60 → warn; `strict` also blocks on high. Allowlist entries are exempt.

### Risk phrase reference (UI summaries / report digests)

| Phrase | Rule(s) |
| --- | --- |
| Install lifecycle scripts / download-then-execute | install-script, download-exec |
| System command execution | danger-child-process |
| Dynamic/obfuscated code execution | dynamic-eval, obfuscation |
| Remote code loading | remote-code-load |
| Credential/data exfiltration | data-exfil |
| Hardcoded keys (API key leak) | hardcoded-secret |
| Reads/writes user files | unsafe-fs |
| Native binaries (cannot be statically reviewed) | native-binary |
| Prototype pollution | prototype-pollution |
| Suspicious package name (typosquat) / suspicious deps | typosquat, suspicious-deps |
| Plain-text network communication | plain-http (skips docs and example domains) |
| Can manipulate the plugin roster | dsh-host-abuse |
| Browser-side data leak | client-browser-risk |
| Cryptocurrency address/mining payload | miner-wallet (low severity note; skips docs) |
| Tarball integrity verification failed | integrity-mismatch |

> `weak-metadata` (missing license/repo) is a package-health note: it appears in the full report but not in the UI risk summary.

## 7. Policy Settings (Settings → security-review)

| Field | Default | Description |
| --- | --- | --- |
| `policy` | `standard` | `standard`: critical→block; `strict`: high also blocks; `audit-only`: record only |
| `autoDisable` | `false` | **Report-only by default** (stability first: avoids harming legitimate plugins or unloading services mid-run). When enabled, the runtime audit disables block-verdict plugins |
| `autoPatchProfile` | `false` | Default: never writes the managed block into the profile `cordis.patch.yml`; when enabled, blocked plugins are not loaded on the next boot |
| `installGate` | `false` | Whether native `dsh plugin add` goes through pre-review. When enabled, the global dsh `lib/bin.js` is patched to inject a review hook (**high-risk operation**, off by default) — **Plan B implementation**: low-frequency injection (no rewrite when already effective), atomic write + `node --check` syntax self-check (rollback on failure), self-cleanup when the plugin is unavailable; also manageable via CLI (below) |
| `allowlist` | `[]` | Exemption list (package names; `*` exempts all) |

### Manual install-gate management (optional)

```sh
dsh-safe-plugin install-gate [--dsh-root <dir>]      # inject (idempotent; skips writing when already effective)
dsh-safe-plugin uninstall-gate [--dsh-root <dir>]    # remove the injection, restore dsh
```

> Default behavior: with `installGate=false`, any leftover injection is automatically removed (restoring the global dsh).

## 8. Stability Guarantees (this plugin will not break dsh)

1. **Zero external dependencies in the module graph**: all `@deepseek-ai/*` imports are **lazy-loaded** from the dsh installation via `host.js` — the plugin entry loads without any external package, so there is no “top-level import failure → dsh fails to boot” path;
2. **apply() is fully exception-isolated**: internal errors only log; the plugin entry can never fail dsh startup;
3. **Fail-open gate**: import-gate resolution/judgment errors always pass through; reviewer failures degrade to warn reports;
4. **Narrowed review scope automatically**: when `dshInstallRoot` cannot be resolved (unusual dsh layouts), only profile-local packages are reviewed — official plugins are never mis-reviewed or no-op'd (prevents agent tools going missing);
5. **install-gate off by default**; writes are atomic + syntax-checked + self-cleaning, and failures never affect dsh. 

## 9. FAQ

### Q1: The settings page shows HTTP 404?
Restarting dsh should fix it (the host API waits up to 8s for webServer to become ready before registering). Still 404: check the dsh terminal log for `设置 API 注册失败`; click “Retry”; refresh the page.

### Q2: Where are the logs?
dsh prints logs to the **terminal window that started it** (stdout/stderr); there is no separate log file. If you cannot find the window, run `npx @deepseek-ai/dsh web *> dsh.log 2>&1` and track with `Get-Content dsh.log -Wait`; in the browser use F12 Console/Network.

### Q3: dsh crashes / agent conversation fails after installing from GitHub?
First make sure you installed the **latest version** (`git pull`, re-push, reinstall). If it still fails, send back the terminal errors mentioning `security-review` / `plugin tree failed to load` / `ERR_MODULE_NOT_FOUND` / `SyntaxError`. Known paths are already eliminated: rc dependencies are optional (install cannot fail on them), the module graph has zero external deps, and the review scope is narrowed to avoid harming official plugins.

### Q4: The uninstall button does nothing / says restart needed?
Uninstall = `pnpm remove` from profile dependencies; the running plugin instance only fully goes away **after restarting dsh** (the UI says so). Official plugins have no uninstall button.

### Q5: Can the review be wrong?
`block` means “strong risk signal”, not “proven malicious”; static analysis cannot cover native binaries, runtime-downloaded code, or heavily obfuscated payloads. Known false-positive sources have been tightened (miner-wallet / plain-http / weak-metadata). Suspected false positives can be exempted in `allowlist` or reviewed manually.

### Q6: Does it work on headless / other profiles?
Yes. Audit/tools/CLI are profile-agnostic; the web settings page and `/api` only exist on web profiles (registration is skipped when there is no webServer).

### Q7: UI did not change after editing the source?
With a `link:` install, host changes take effect after restart; **client-bundle changes need a hard refresh (Ctrl+F5)** or a dsh restart so `/plugins` re-serves the bundle.

## 10. Known Limitations (honest disclosure)

1. Static analysis cannot cover native binaries, runtime-downloaded code, or heavily obfuscated payloads;
2. Transitive dependencies are checked by name heuristics only (no per-file scan of the whole tree);
3. The runtime gate deterministically intercepts plugin imports that happen after this plugin applies; plugins starting earlier in the same boot batch load for a few milliseconds before the boot audit covers them (report-only by default);
4. If a blocked plugin provides services other rows `inject`, disabling it (when `autoDisable` is on) fails boot loudly with the missing service named — that is dsh's fail-loud contract;
5. When `dshInstallRoot` cannot be resolved, the review scope narrows to profile-local packages (stability first);
6. The client is a hand-written ModuleLoader bundle, not validated by a bundler — if the settings entry/UI misbehaves, check the browser Console and dsh terminal logs first.

## 11. Development

```sh
# Get the source (any path) and enter it:
#   git clone https://github.com/ateen18/dsh-plugin-security-review && cd dsh-plugin-security-review
cd <your-plugin-source-dir>
npm test            # unit tests (analyzer + install-gate + watcher; zero deps)
npm run check        # 全量语法校验（node --check 真实解析器）
```

### Directory layout

```text
lib/
├── index.js          host plugin (audit, settings section, tools, webServer API registration, watcher)
├── api.js            HTTP API (list/run/uninstall; loopback-protected)
├── client.js         browser settings-page module (ModuleLoader bundle, loader-fallback guard)
├── gate.js           import gate (EntryTree.prototype.import patch + scope check + fail-open)
├── host.js           dsh host-package resolution (lazy @deepseek-ai/* from the dsh install)
├── install-gate.js   native `dsh plugin add` review hook (low-frequency inject + atomic write + self-check + self-clean)
├── watcher.js        profile package.json change watcher (fallback for direct pnpm installs)
├── store.js          report/cache persistence
├── patch-manager.js  managed block editor for profile cordis.patch.yml
├── settings.js       settings-section schema and wiring
├── tools.js          in-session tools (security_review / security_review_status)
└── analyzer/         pure static analyzer (zero deps)
    ├── rules.js      rule engine (20 rules)
    ├── score.js      scoring, verdicts, policy, RISK_LABELS and verdict-aligned summaries
    ├── tar.js        tgz extraction (path-traversal / zip-bomb safe)
    ├── registry.js   registry metadata / version selection / tarball integrity
    ├── semver.js     minimal semver
    ├── known.js      known-package-name list (typosquat comparison)
    └── render.js     Markdown report rendering
docs/                design docs, user guide and fix/optimization records
test/               npm tests plus evil/benign fixtures
```

### Related documents

- `docs/design.md` — architecture and threat model
- `docs/使用说明.md` — Chinese user guide (this document's Chinese counterpart)
- `docs/2026-08-18-启动崩溃问题修复报告.md` / `docs/2026-08-20-install-gate启动崩溃修复报告.md` — crash-fix records
- `docs/2026-08-20-web-ui-优化记录.md` — Web UI module development and issue log
- `docs/2026-08-20-跨机安装崩溃排查与加固报告.md` — cross-machine install investigation and hardening

## 12. Publishing and Installing for Others

```sh
# Publisher:
cd <your-plugin-source-dir>
npm login && npm publish

# Users:
npm i -g dsh-plugin-security-review
dsh plugin --profile web add dsh-plugin-security-review
dsh-safe-plugin add dsh-plugin-security-review
```

GitHub: `https://github.com/ateen18/dsh-plugin-security-review` (MIT).