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
    const API = {
      list: () => srFetch("/api/security-review/list"),
      run: () => srFetch("/api/security-review/run", {}),
      uninstall: (name) => srFetch("/api/security-review/uninstall", { name }),
      review: (target) => srFetch("/api/security-review/review", { target }),
      install: (target, force) => srFetch("/api/security-review/install", { target, force }),
      gateStatus: () => srFetch("/api/security-review/gate"),
      gateSet: (enable) => srFetch("/api/security-review/gate", { enable })
    };

    async function srFetch(path, body) {
      const response = await fetch(path, body === undefined ? {} : {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body)
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        if (response.status === 404) throw new Error("host API 未注册（" + path + "）：请重启 dsh 后重试");
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

    function SecurityReviewSection(props) {
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

      const onUninstall = async (row) => {
        const name = row.name;
        if (!window.confirm("确定卸载 " + name + "？\n\n卸载后会从 profile 依赖中移除；完全生效需重启 dsh。")) return;
        setUninstalling(name);
        setError(null);
        try {
          const result = await API.uninstall(name);
          setNotice(result?.ok ? "已卸载 " + name + "（重启后完全生效）" : (result?.message ?? "卸载失败"));
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
        gateRow: { display: "flex", alignItems: "center", gap: 10, fontSize: 12, color: "#57606a" }
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
          gate ? React.createElement("div", { style: styles.gateRow },
            React.createElement("span", null, "install-gate（让原生 dsh plugin add 也走预审）：" + (gate.enabled ? "已开启" : "已关闭")),
            React.createElement("button", { style: gate.enabled ? styles.warnBtn : styles.button, disabled: gateBusy, onClick: toggleGate }, gateBusy ? "处理中…" : (gate.enabled ? "关闭" : "开启"))
          ) : null
        ),
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
      ctx.locale.register(NS, { zh, en });
      ctx.slots.inject("settings.section", () => {
        const unregister = ctx.slots.register({
          name: "settings.section",
          id: "security-review",
          order: 200,
          label: () => ctx.locale.bind(NS)("nav.title"),
          locale: NS,
          inject: () => ({})
        }, SecurityReviewSection);
        return () => unregister();
      });
    }

    exports.apply = apply;
    exports.inject = ["slots", "locale"];
    return module.exports;
  }
});
}
