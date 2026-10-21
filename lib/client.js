/**
 * 客户端半侧（浏览器 / 桌面客户端渲染进程）。
 *
 * 加载协议在两代 dsh 里是一致的：宿主把 `lib/client.js` 作为一个惰性 CJS
 * bundle 提供给页面，bundle 顶层只调用 `window.__ModuleLoader__.load({id, factory})`
 * 注册工厂，模块副作用留在 factory 闭包里，首次物化时才执行。因此这里没有
 * 顶层 import、没有构建步骤。
 *
 * 桌面客户端（Electron）与 web 版共用同一份页面：页面从 127.0.0.1 的本机宿主
 * 加载，`document.baseURI` 就是宿主根地址，所以 API 一律用相对 URL 解析——
 * 既不用写死端口，也不受页面是否带认证查询串影响。
 */
if (typeof window.__ModuleLoader__ === "undefined" || typeof window.__ModuleLoader__.load !== "function") {
  console.warn("[security-review] client module loader unavailable; settings section skipped");
} else {
window.__ModuleLoader__.load({
  id: "dsh-plugin-security-review",
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;
    Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
    let React = require("react");

    const NS = "security-review";
    const ROUTE = "api/security-review/";

    /** 把路由解析成宿主根地址下的绝对 URL（web / 桌面同源）。 */
    function apiUrl(name) {
      const base = typeof document !== "undefined" && document.baseURI ? document.baseURI : "http://127.0.0.1/";
      return new URL(ROUTE + name, base).toString();
    }

    const API = {
      list: () => srFetch("list"),
      run: () => srFetch("run", {}),
      uninstall: (name) => srFetch("uninstall", { name }),
      review: (target) => srFetch("review", { target }),
      install: (target, force) => srFetch("install", { target, force }),
      settings: () => srFetch("settings"),
      saveSettings: (settings) => srFetch("settings", { settings }),
      capabilities: () => srFetch("capabilities"),
      gateStatus: () => srFetch("gate"),
      gateSet: (enable) => srFetch("gate", { enable })
    };

    async function srFetch(name, body) {
      const response = await fetch(apiUrl(name), body === undefined ? {} : {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body)
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        if (response.status === 404) {
          throw new Error("宿主 API 未注册（" + name + "）：请先让插件在宿主里加载成功（重启 dsh / 检查插件日志）后重试");
        }
        throw new Error(data?.error ?? ("HTTP " + response.status));
      }
      return data;
    }

    const DOT_COLORS = {
      safe: "#22c55e",
      warn: "#eab308",
      danger: "#ef4444",
      unknown: "#94a3b8",
      builtin: "#94a3b8"
    };
    const VERDICT_TEXT = {
      pass: "通过",
      warn: "有风险",
      block: "危险",
      audit: "仅审计",
      builtin: "内置插件",
      unknown: "未审查"
    };
    const POLICY_TEXT = {
      standard: "标准（critical/低分拦截，high 警告）",
      strict: "严格（high 也拦截）",
      "audit-only": "仅审计（只报告，不拦截）"
    };

    function riskDot(risk) {
      const color = DOT_COLORS[risk] ?? DOT_COLORS.unknown;
      return React.createElement("span", {
        style: {
          display: "inline-block",
          width: 10, height: 10, borderRadius: "50%",
          backgroundColor: color, flexShrink: 0, marginTop: 4
        },
        title: risk
      });
    }

    function SecurityReviewSection() {
      const [rows, setRows] = React.useState([]);
      const [loading, setLoading] = React.useState(true);
      const [reviewing, setReviewing] = React.useState(false);
      const [uninstalling, setUninstalling] = React.useState(null);
      const [error, setError] = React.useState(null);
      const [notice, setNotice] = React.useState(null);
      const [safeOpen, setSafeOpen] = React.useState(false);
      const [target, setTarget] = React.useState("");
      const [toolBusy, setToolBusy] = React.useState(false);
      const [toolResult, setToolResult] = React.useState(null);
      const [gate, setGate] = React.useState(null);
      const [gateBusy, setGateBusy] = React.useState(false);
      const [caps, setCaps] = React.useState(null);
      const [form, setForm] = React.useState(null);
      const [formOpen, setFormOpen] = React.useState(false);
      const [saving, setSaving] = React.useState(false);

      const load = React.useCallback(async (run) => {
        setError(null);
        if (run) setReviewing(true); else setLoading(true);
        try {
          const data = run ? await API.run() : await API.list();
          setRows(Array.isArray(data.rows) ? data.rows : []);
          if (run && data.summary) setNotice(data.summary);
        } catch (e) {
          setError(e?.message ?? String(e));
        } finally {
          setLoading(false);
          setReviewing(false);
        }
      }, []);

      React.useEffect(() => { load(false); }, [load]);
      React.useEffect(() => {
        API.gateStatus().then((g) => setGate(g), () => setGate(null));
        API.capabilities().then((c) => setCaps(c), () => setCaps(null));
        API.settings().then((s) => {
          const value = s?.settings;
          // 白名单在界面上按行编辑：加载时就把它摊成文本，避免"只改策略"时
          // 空文本覆盖掉已有白名单。
          setForm(value ? { ...value, allowlistText: (value.allowlist ?? []).join("\n") } : null);
        }, () => setForm(null));
      }, []);

      const runReview = async () => {
        const spec = target.trim();
        if (!spec) return;
        setToolBusy(true); setError(null);
        try {
          const r = await API.review(spec);
          setToolResult({ kind: "review", data: r });
        } catch (e) { setError(e?.message ?? String(e)); }
        finally { setToolBusy(false); }
      };
      const runInstall = async (force) => {
        const spec = target.trim();
        if (!spec) return;
        setToolBusy(true); setError(null);
        try {
          const r = await API.install(spec, force);
          setToolResult({ kind: "install", data: r });
          if (r.ok) {
            setNotice(r.message + (r.requiresRestart ? "（重启后完全生效）" : ""));
            await load(false);
          }
        } catch (e) { setError(e?.message ?? String(e)); }
        finally { setToolBusy(false); }
      };
      const toggleGate = async () => {
        if (!gate?.supported) return;
        const action = gate.enabled ? "关闭" : "开启";
        if (!window.confirm(action + " install-gate 会改写全局 dsh 的 lib/bin.js（高危操作，默认关闭）。确定" + action + "？")) return;
        setGateBusy(true); setError(null);
        try {
          const r = await API.gateSet(!gate.enabled);
          setGate({ ...gate, enabled: !gate.enabled });
          setNotice(r.message ?? (action + "成功"));
        } catch (e) { setError(e?.message ?? String(e)); }
        finally { setGateBusy(false); }
      };

      const saveSettings = async () => {
        if (!form) return;
        setSaving(true); setError(null);
        try {
          const payload = {
            ...form,
            allowlist: String(form.allowlistText ?? "")
              .split(/[\n,]/)
              .map((item) => item.trim())
              .filter(Boolean)
          };
          delete payload.allowlistText;
          const r = await API.saveSettings(payload);
          setForm({ ...r.settings, allowlistText: (r.settings.allowlist ?? []).join("\n") });
          setNotice("策略已保存并立即生效");
          if (caps) await runReviewQuietly();
        } catch (e) {
          setError(e?.message ?? String(e));
        } finally {
          setSaving(false);
        }
      };

      const runReviewQuietly = async () => {
        try {
          const data = await API.run();
          setRows(Array.isArray(data.rows) ? data.rows : []);
          if (data.summary) setNotice(data.summary);
        } catch {}
      };

      const onUninstall = async (row) => {
        const name = row.name;
        if (!window.confirm("确定卸载 " + name + "？\n\n卸载后会从 profile 依赖中移除；完全生效需重启 dsh。")) return;
        setUninstalling(name);
        setError(null);
        try {
          const result = await API.uninstall(name);
          setNotice(result?.ok ? "已卸载 " + name + (result.requiresRestart ? "（重启后完全生效）" : "") : (result?.message ?? "卸载失败"));
          await load(false);
        } catch (e) {
          setError(e?.message ?? String(e));
        } finally {
          setUninstalling(null);
        }
      };

      const groups = { danger: [], warn: [], safe: [] };
      for (const row of rows) {
        if (row.official) groups.safe.push(row);
        else if (row.risk === "danger") groups.danger.push(row);
        else if (row.risk === "warn") groups.warn.push(row);
        else groups.safe.push(row);
      }

      const summaryText = (row) => row.riskSummary ?? row.summary ?? (row.reviewed ? "已审查" : "尚未审查，点击上方按钮执行一键审查");

      const renderRow = (row) => {
        const risk = row.official ? "builtin" : (row.risk ?? "unknown");
        const nameText = row.name + (row.version && row.version !== "?" ? "  v" + row.version : "");
        return React.createElement("li", { key: row.id, style: styles.item },
          riskDot(risk),
          React.createElement("div", { style: styles.meta },
            React.createElement("div", { style: styles.name }, nameText),
            React.createElement("div", { style: styles.summary }, summaryText(row))
          ),
          row.official ? React.createElement("span", { style: styles.badge }, VERDICT_TEXT.builtin)
            : (row.reviewed ? React.createElement("span", { style: styles.badge }, VERDICT_TEXT[row.verdict] ?? row.verdict) : null),
          !row.official ? React.createElement("button", {
            style: styles.uninstall,
            disabled: uninstalling !== null,
            onClick: () => onUninstall(row),
            title: "从 profile 依赖中移除（重启后完全生效）"
          }, uninstalling === row.name ? "卸载中…" : "卸载") : null
        );
      };

      const renderGroup = (title, list, color) => {
        if (!list.length) return null;
        return React.createElement("div", { key: title, style: { display: "flex", flexDirection: "column", gap: 8 } },
          React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 8 } },
            React.createElement("span", { style: { width: 8, height: 8, borderRadius: "50%", backgroundColor: color } }),
            React.createElement("span", { style: { fontSize: 13, fontWeight: 600, color: "#24292f" } }, title + "（" + list.length + "）")
          ),
          React.createElement("ul", { style: styles.list }, list.map(renderRow))
        );
      };

      const styles = {
        root: { display: "flex", flexDirection: "column", gap: 14, padding: "4px 2px" },
        bar: { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 },
        title: { margin: 0, fontSize: 15, fontWeight: 600 },
        button: {
          border: "1px solid #d0d7de", background: "#f6f8fa", borderRadius: 6,
          padding: "6px 12px", cursor: "pointer", fontSize: 13
        },
        list: { listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 8 },
        item: {
          border: "1px solid #e3e7ec", borderRadius: 8, padding: "10px 12px",
          display: "flex", gap: 10, alignItems: "flex-start", background: "#fff"
        },
        meta: { flex: 1, minWidth: 0 },
        name: { fontSize: 13, fontWeight: 600, wordBreak: "break-all" },
        summary: { fontSize: 12, color: "#57606a", marginTop: 3, lineHeight: 1.5, wordBreak: "break-word" },
        badge: {
          fontSize: 11, color: "#57606a", border: "1px solid #d0d7de", borderRadius: 999,
          padding: "1px 8px", flexShrink: 0, marginTop: 1
        },
        uninstall: {
          border: "1px solid #f0c0c0", background: "#fff5f5", color: "#c0392b",
          borderRadius: 6, padding: "4px 10px", cursor: "pointer", fontSize: 12, flexShrink: 0
        },
        fold: {
          border: "1px solid #d0d7de", background: "transparent", borderRadius: 6,
          padding: "4px 10px", cursor: "pointer", fontSize: 12, color: "#57606a"
        },
        error: { display: "flex", alignItems: "center", gap: 10, fontSize: 12, color: "#c0392b", background: "#fff5f5", border: "1px solid #f0c0c0", borderRadius: 6, padding: "8px 10px" },
        notice: { fontSize: 12, color: "#1a7f37", background: "#f0fff4", border: "1px solid #c6f0d2", borderRadius: 6, padding: "8px 10px" },
        panel: { border: "1px solid #e3e7ec", borderRadius: 8, padding: "12px", display: "flex", flexDirection: "column", gap: 10, background: "#fafbfc" },
        panelTitle: { margin: 0, fontSize: 13, fontWeight: 600, color: "#24292f" },
        row: { display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" },
        input: { flex: 1, minWidth: 200, border: "1px solid #d0d7de", borderRadius: 6, padding: "6px 10px", fontSize: 13, background: "#fff" },
        primaryBtn: { border: "1px solid #2da44e", background: "#2da44e", color: "#fff", borderRadius: 6, padding: "6px 12px", cursor: "pointer", fontSize: 13 },
        warnBtn: { border: "1px solid #d0d7de", background: "#fff5f5", color: "#c0392b", borderRadius: 6, padding: "6px 12px", cursor: "pointer", fontSize: 13 },
        result: { border: "1px solid #e3e7ec", borderRadius: 6, padding: "10px", fontSize: 12, background: "#fff", display: "flex", flexDirection: "column", gap: 6 },
        gateRow: { display: "flex", alignItems: "center", gap: 10, fontSize: 12, color: "#57606a", flexWrap: "wrap" },
        field: { display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "#57606a" },
        select: { border: "1px solid #d0d7de", borderRadius: 6, padding: "6px 8px", fontSize: 13, background: "#fff" },
        textarea: { border: "1px solid #d0d7de", borderRadius: 6, padding: "6px 8px", fontSize: 12, minHeight: 60, background: "#fff", fontFamily: "inherit" },
        check: { display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "#24292f" },
        hint: { fontSize: 11, color: "#8b949e" }
      };

      const isBusy = loading || reviewing;
      return React.createElement("div", { style: styles.root },
        React.createElement("div", { style: styles.bar },
          React.createElement("h3", { style: styles.title }, "插件安全审查"),
          React.createElement("button", {
            style: styles.button,
            disabled: isBusy,
            onClick: () => load(true),
            title: "对当前全部已安装插件执行一次完整静态审查"
          }, reviewing ? "审查中…" : "一键安全审查")
        ),
        caps ? React.createElement("div", { style: styles.gateRow },
          React.createElement("span", null, caps.desktop ? "运行环境：桌面客户端" : "运行环境：web"),
          React.createElement("span", null, "· 安装通道：" + (caps.packages?.via ?? caps.packages ?? "-")),
          React.createElement("span", null, "· profile：" + (caps.profile?.name ?? "-"))
        ) : null,
        React.createElement("div", { style: styles.panel },
          React.createElement("h4", { style: styles.panelTitle }, "审查 / 安装工具"),
          React.createElement("div", { style: styles.row },
            React.createElement("input", {
              style: styles.input,
              value: target,
              onChange: (e) => setTarget(e.target.value),
              placeholder: "插件名 / 本地目录 / git URL / .tgz 地址",
              onKeyDown: (e) => { if (e.key === "Enter") runReview(); }
            }),
            React.createElement("button", { style: styles.button, disabled: toolBusy || !target.trim(), onClick: runReview }, "审查"),
            React.createElement("button", { style: styles.primaryBtn, disabled: toolBusy || !target.trim(), onClick: () => runInstall(false) }, toolBusy ? "处理中…" : "安全安装")
          ),
          toolResult ? React.createElement("div", { style: styles.result },
            React.createElement("div", null,
              (toolResult.kind === "review" ? "审查结果：" : "安装结果：") + (toolResult.data?.report?.verdict ?? "?") +
              (typeof toolResult.data?.report?.score === "number" ? "（评分 " + toolResult.data.report.score + "）" : "") +
              (toolResult.data?.report?.riskSummary ? " — " + toolResult.data.report.riskSummary : "")
            ),
            toolResult.data?.ok === false && toolResult.data?.reason === "needs-confirm"
              ? React.createElement("button", { style: styles.warnBtn, onClick: () => runInstall(true) }, "确认风险并强制安装")
              : null,
            toolResult.data?.ok === false && toolResult.data?.reason === "blocked"
              ? React.createElement("button", { style: styles.warnBtn, onClick: () => runInstall(true) }, "强制放行（风险自担）")
              : null,
            toolResult.data?.message ? React.createElement("div", null, toolResult.data.message) : null
          ) : null,
          gate && !gate.supported ? React.createElement("div", { style: styles.gateRow },
            React.createElement("span", null, "install-gate：" + (gate.reason === "packaged-runtime"
              ? "桌面客户端不可用（运行时打包在 app.asar 内，不能改写 dsh 的 lib/bin.js）"
              : "当前运行时不可用（" + gate.reason + "）")),
            React.createElement("span", { style: styles.hint }, "安装预审请用上面的“安全安装”或 dsh-safe-plugin CLI")
          ) : null,
          gate && gate.supported ? React.createElement("div", { style: styles.gateRow },
            React.createElement("span", null, "install-gate（让原生 dsh plugin add 也走预审）：" + (gate.enabled ? "已开启" : "已关闭")),
            React.createElement("button", { style: gate.enabled ? styles.warnBtn : styles.button, disabled: gateBusy, onClick: toggleGate }, gateBusy ? "处理中…" : (gate.enabled ? "关闭" : "开启"))
          ) : null
        ),
        form ? React.createElement("div", { style: styles.panel },
          React.createElement("div", { style: styles.row },
            React.createElement("h4", { style: styles.panelTitle }, "策略"),
            React.createElement("button", { style: styles.fold, onClick: () => setFormOpen(!formOpen) }, formOpen ? "▾ 收起" : "▸ 展开")
          ),
          formOpen ? React.createElement("div", { style: { display: "flex", flexDirection: "column", gap: 10 } },
            React.createElement("label", { style: styles.field },
              "审查策略",
              React.createElement("select", {
                style: styles.select,
                value: form.policy,
                onChange: (e) => setForm({ ...form, policy: e.target.value })
              }, Object.keys(POLICY_TEXT).map((key) => React.createElement("option", { key, value: key }, POLICY_TEXT[key])))
            ),
            React.createElement("label", { style: styles.check },
              React.createElement("input", {
                type: "checkbox",
                checked: form.autoDisable === true,
                onChange: (e) => setForm({ ...form, autoDisable: e.target.checked })
              }),
              "判定为危险时自动禁用插件（运行期）"
            ),
            React.createElement("label", { style: styles.check },
              React.createElement("input", {
                type: "checkbox",
                checked: form.autoPatchProfile === true,
                onChange: (e) => setForm({ ...form, autoPatchProfile: e.target.checked })
              }),
              "把拦截写进 profile 的 cordis.patch.yml（下次启动也不加载）"
            ),
            React.createElement("label", { style: styles.field },
              "白名单（每行一个包名，* 表示全部放行）",
              React.createElement("textarea", {
                style: styles.textarea,
                value: form.allowlistText ?? (form.allowlist ?? []).join("\n"),
                onChange: (e) => setForm({ ...form, allowlistText: e.target.value })
              })
            ),
            React.createElement("div", { style: styles.row },
              React.createElement("button", { style: styles.primaryBtn, disabled: saving, onClick: saveSettings }, saving ? "保存中…" : "保存策略"),
              React.createElement("span", { style: styles.hint }, "保存后立即作用到导入门禁与启动审计")
            )
          ) : null
        ) : null,
        error ? React.createElement("div", { style: styles.error, role: "alert" },
          "错误：" + error,
          React.createElement("button", { style: styles.button, onClick: () => load(false) }, "重试")
        ) : null,
        notice ? React.createElement("div", { style: styles.notice, role: "status" }, notice) : null,
        renderGroup("危险插件", groups.danger, "#ef4444"),
        renderGroup("有风险插件", groups.warn, "#eab308"),
        React.createElement("div", { key: "safe-fold", style: { display: "flex", flexDirection: "column", gap: 8 } },
          React.createElement("div", { style: { display: "flex", alignItems: "center", gap: 8 } },
            React.createElement("span", { style: { width: 8, height: 8, borderRadius: "50%", backgroundColor: "#22c55e" } }),
            React.createElement("span", { style: { fontSize: 13, fontWeight: 600, color: "#24292f" } }, "安全插件（" + groups.safe.length + "）"),
            React.createElement("button", { style: styles.fold, onClick: () => setSafeOpen(!safeOpen) },
              safeOpen ? "▾ 收起" : "▸ 展开"
            )
          ),
          safeOpen ? React.createElement("ul", { style: styles.list }, groups.safe.map(renderRow)) : null
        )
      );
    }

    const zh = {
      "nav.title": "插件安全审查"
    };
    const en = {
      "nav.title": "Plugin Security Review"
    };

    function apply(ctx) {
      // 客户端条目激活失败会让桌面端直接判定「entry did not activate」并拒绝启动，
      // 所以这里整体兜底：任何意外只记录，绝不让一个设置页分区拖垮宿主。
      try {
        // cordis 4 只允许在 exports.inject 声明过的服务上用 `ctx.<name>` 取值；未注入的
        // 属性会抛 `cannot get property "..." without inject`。locale 是可选的，所以用
        // ctx.get 取，取不到就退回内置中文。
        let locale = null;
        try {
          locale = typeof ctx.get === "function" ? ctx.get("locale") : null;
        } catch {
          locale = null;
        }
        const t = (key) => {
          try {
            return locale ? locale.bind(NS)(key) : (zh[key] ?? key);
          } catch {
            return zh[key] ?? key;
          }
        };
        if (locale?.register) {
          try { locale.register(NS, { zh, en }); } catch (error) { console.warn("[security-review] locale register failed", error); }
        }
        ctx.effect(() => ctx.slots.inject("settings.section", () => {
          const unregister = ctx.slots.register({
            name: "settings.section",
            id: "security-review",
            order: 200,
            label: () => t("nav.title"),
            locale: NS,
            inject: () => ({})
          }, SecurityReviewSection);
          return () => unregister();
        }), "security-review: settings section");
      } catch (error) {
        console.warn("[security-review] client apply failed; settings section skipped", error);
      }
    }

    exports.apply = apply;
    exports.inject = ["slots"];
    return module.exports;
  }
});
}
