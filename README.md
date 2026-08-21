# dsh-plugin-security-review

A security review plugin for DeepSeek Harness (dsh) plugins. Once installed, every
other plugin is statically reviewed before it is installed or loaded: dangerous code,
vulnerabilities, and supply-chain risks are analyzed, a review report is produced,
and an install recommendation is given. At runtime it keeps auditing the installed
roster and disables dangerous plugins.

See [README.zh.md](./README.zh.md) for the Chinese quick start.

**Full user guides**:
- English: [docs/USER_GUIDE.en.md](./docs/USER_GUIDE.en.md)
- 中文（简体）: [docs/使用说明.md](./docs/使用说明.md)

## Three layers

| Layer | When | What it does |
| --- | --- | --- |
| 1. Install gate | before install (`dsh-safe-plugin add`) | downloads source **without running any install scripts**, analyzes it, prints the report; `block` refuses the install, `warn` needs confirmation, `pass` forwards to `dsh plugin add --ignore-scripts` |
| 2. Runtime gate | after dsh boots | audits every out-of-tree plugin in the profile (cached); `block`ed plugins are disabled via `loader.update(id,{disabled:true})` and written into a managed `disabled: true` block in the profile's `cordis.patch.yml`, so their code is never imported on the next boot |
| 3. In-session tools | during sessions | `security_review` / `security_review_status` tools review any plugin/source directory and read historical reports |

## Install

```sh
dsh-safe-plugin add dsh-plugin-security-review
# or: dsh plugin --profile web add dsh-plugin-security-review
```

The package declares `dsh.bundle`, so the dsh plugin manager joins it into
`dsh.profile.bundles` automatically.

## Review and install other plugins

```sh
dsh-safe-plugin add dsh-plugin-foo       # review + install
dsh-safe-plugin add ./local-plugin-dir
dsh-safe-plugin add https://github.com/me/plugin.git
dsh-safe-plugin review dsh-plugin-foo   # review only
dsh-safe-plugin review . --ignore test/fixtures   # skip fixtures dirs
dsh-safe-plugin list                    # historical reports
dsh-safe-plugin verify                  # re-review installed plugins
```

## Reports

- Score (0-100), verdict `pass / warn / block / audit`, per-finding detail
  (severity, category, file:line, snippet, recommendation) and an install
  recommendation.
- Persisted under `$DSH_HOME/security-review/`: `reports/latest/<name>.md`
  (markdown), `reports/history/*.json`, `index.json`.
- The web settings UI gains a `security-review` section (policy,
  auto-disable switch, allowlist).

## Known limitations

1. Static analysis cannot cover native binaries, runtime-downloaded code, or
   heavily obfuscated payloads; `block` means strong risk signals, not proof
   of malice.
2. The runtime gate deterministically blocks plugin imports that happen after
   this plugin applies; plugins that start earlier in the same boot batch
   load for a few milliseconds before the boot audit disables them, and the
   managed patch block keeps them from loading on the next boot. Use
   `dsh-safe-plugin add` for deterministic pre-install blocking.
3. Blocking a plugin that provides services other rows `inject` fails boot
   loudly with the missing service named — that is dsh's fail-loud contract.
4. Transitive dependencies are checked by name heuristics only (no full
   source scan of the whole dependency tree).
5. A review-engine failure degrades to `warn` (fail-open) so the reviewer
   itself can never brick dsh; re-check with `dsh-safe-plugin verify`.

## Development

```sh
npm test      # analyzer unit tests (no dsh needed; run from this dir)
```

License: MIT