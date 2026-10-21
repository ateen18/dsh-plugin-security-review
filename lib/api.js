/**
 * 宿主 HTTP API（设置分区用）。
 *
 * 同一来源下的 JSON 路由，挂在 `/api/security-review/` 下：
 *
 *   GET/POST list?         — list 只读
 *   POST run               一键复审全部
 *   POST review            审查任意目标（目录 / npm 包 / git / tgz）
 *   POST install           安装任意目标（可选 force）
 *   POST uninstall         卸载 profile 依赖
 *   GET  settings          读策略
 *   POST settings          写策略（立即生效）
 *   GET  capabilities      当前运行环境（桌面 / web、安装通道、install-gate 支持）
 *   GET  gate              install-gate 状态
 *   POST gate              开关 install-gate
 *
 * 两条硬约束：
 *
 *   1. **仅本机回环**：桌面客户端的页面和 web 版页面都从 127.0.0.1 加载，但路由
 *      本身不依赖页面来源，因此仍按 socket 远端地址拒绝非回环请求（LAN → 403）。
 *   2. **一条路径一个路由**：0.2.x 的 `webServer.register()` 以 `(kind, path)` 为键，
 *      同路径重复注册会抛 "duplicate exact route"。因此同一路径的 GET/POST 必须
 *      合成一条按方法分派的处理器——否则抛出会中断后续所有路由的注册。
 */

function isLoopbackAddress(address) {
  return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1" || address === undefined || address === null;
}

function isLoopbackRequest(request) {
  try {
    return isLoopbackAddress(request.socket?.remoteAddress);
  } catch {
    return false;
  }
}

function json(res, status, body) {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body));
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > 64 * 1024) {
        reject(new Error("body-too-large"));
        queueMicrotask(() => req.destroy());
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (chunks.length === 0) { resolve({}); return; }
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
      catch { reject(new Error("invalid-json")); }
    });
    req.on("error", reject);
  });
}

function guard(req, res) {
  if (isLoopbackRequest(req)) return true;
  json(res, 403, { ok: false, error: "forbidden: loopback-only" });
  return false;
}

/**
 * 一条路由同时承载多个方法。
 * @param pathname - 精确路径。
 * @param handlers - `{GET: () => value, POST: (body) => value}`；未列出的方法返回 405。
 * @returns `webServer.register()` 可直接消费的路由对象。
 */
export function methodRoute(pathname, handlers) {
  return {
    kind: "exact",
    path: pathname,
    handler: (req, res) => {
      if (!guard(req, res)) return;
      const allowed = Object.keys(handlers);
      if (!allowed.includes(req.method)) {
        res.writeHead(405, { "content-type": "application/json; charset=utf-8", allow: allowed.join(", ") });
        res.end(JSON.stringify({ ok: false, error: "method-not-allowed" }));
        return;
      }
      const respond = (promise) => Promise.resolve(promise).then(
        (value) => json(res, res.status && res.status !== 200 ? res.status : 200, value),
        (error) => json(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) })
      );
      if (req.method === "GET") {
        return respond(handlers.GET());
      }
      return readJsonBody(req).then((body) => respond(handlers.POST(typeof body === "object" && body !== null ? body : {})));
    }
  };
}

/**
 * 注册 API 路由。`service` 需提供：list / runReview / reviewTarget /
 * installTarget / uninstall / settings / updateSettings / capabilities /
 * gateStatus / gateSet。每条路由都是 `webServer.register()` 可直接消费的形状。
 */
export function buildSecurityReviewApi(service) {
  return [
    methodRoute("/api/security-review/list", {
      GET: () => service.list()
    }),
    methodRoute("/api/security-review/run", {
      POST: () => service.runReview()
    }),
    methodRoute("/api/security-review/uninstall", {
      POST: (body) => {
        const name = typeof body.name === "string" ? body.name.trim() : "";
        if (!name) throw new Error("missing-name");
        return service.uninstall(name);
      }
    }),
    methodRoute("/api/security-review/review", {
      POST: (body) => {
        const target = typeof body.target === "string" ? body.target.trim() : "";
        if (!target) throw new Error("missing-target");
        return service.reviewTarget(target, {});
      }
    }),
    methodRoute("/api/security-review/install", {
      POST: (body) => {
        const target = typeof body.target === "string" ? body.target.trim() : "";
        if (!target) throw new Error("missing-target");
        return service.installTarget(target, { force: body.force === true });
      }
    }),
    methodRoute("/api/security-review/settings", {
      GET: () => service.settings(),
      POST: (body) => service.updateSettings(body)
    }),
    methodRoute("/api/security-review/capabilities", {
      GET: () => service.capabilities()
    }),
    methodRoute("/api/security-review/gate", {
      GET: () => service.gateStatus(),
      POST: (body) => service.gateSet(body.enable === true)
    })
  ];
}
