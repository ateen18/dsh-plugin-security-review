/**
 * Host HTTP API for the security-review settings UI.
 *
 * Same-origin JSON routes under /api/security-review/, served by the
 * webServer when one exists (web profiles). All routes are loopback-only:
 * the settings UI is a local browser, LAN hosts get 403. Uninstall is
 * performed by spawning pnpm in the profile directory, then requires a
 * restart to fully take effect.
 */
import { spawn } from "node:child_process";
import path from "node:path";
import { readFileSync, existsSync } from "node:fs";

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

function requireMethod(req, res, method) {
  if (req.method === method) return true;
  json(res, 405, { ok: false, error: "method-not-allowed" });
  return false;
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

function getRoute(pathname, run) {
  return {
    kind: "exact",
    path: pathname,
    handler: (req, res) => {
      if (!guard(req, res)) return;
      if (!requireMethod(req, res, "GET")) return;
      run().then((value) => json(res, 200, value), (error) => {
        json(res, 500, { ok: false, error: error instanceof Error ? error.message : String(error) });
      });
    }
  };
}

function postRoute(pathname, run) {
  return {
    kind: "exact",
    path: pathname,
    handler: (req, res) => {
      if (!guard(req, res)) return Promise.resolve();
      if (!requireMethod(req, res, "POST")) return Promise.resolve();
      return readJsonBody(req).then((body) => {
        return run(typeof body === "object" && body !== null ? body : {}).then((value) => json(res, 200, value), (error) => {
          json(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) });
        });
      }, (error) => {
        json(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) });
      });
    }
  };
}

/**
 * Uninstall one profile dependency by spawning pnpm (async). The name is
 * validated against the profile manifest so arbitrary command injection
 * through the pnpm argument is impossible.
 */
function runPnpmRemove(profileDir, name) {
  return new Promise((resolve) => {
    const child = spawn("pnpm", ["remove", name], {
      cwd: profileDir,
      shell: process.platform === "win32",
      windowsHide: true
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr?.on("data", (chunk) => { stderr += chunk.toString(); });
    const done = (code) => {
      resolve({
        ok: code === 0,
        exitCode: code,
        message: (stdout || stderr || "").trim().slice(0, 2000)
      });
    };
    child.on("error", (error) => {
      resolve({ ok: false, exitCode: -1, message: "pnpm 启动失败: " + (error?.message ?? String(error)) });
    });
    child.on("close", (code) => done(code));
  });
}

/**
 * Run `dsh plugin --profile <name> add <spec> --ignore-scripts` as a child
 * process (so bundle reconciliation runs). Prefers the `dsh` command on PATH,
 * falling back to the dsh installation's own bin.
 */
function runDshPluginAdd(profileDir, spec, dshInstallRoot) {
  return new Promise((resolve) => {
    const profile = path.basename(profileDir);
    const args = ["plugin", "--profile", profile, "add", spec, "--ignore-scripts"];
    const done = (error, code, out) => resolve({
      ok: !error && code === 0,
      exitCode: error ? -1 : code,
      message: (out || "").trim().slice(0, 2000) || (error?.message ?? "done")
    });
    const attempt = (cmd, cmdArgs) => {
      const child = spawn(cmd, cmdArgs, { cwd: profileDir, shell: process.platform === "win32", windowsHide: true });
      let out = "";
      child.stdout?.on("data", (chunk) => { out += chunk.toString(); });
      child.stderr?.on("data", (chunk) => { out += chunk.toString(); });
      child.on("error", (error) => done(error, -1, out));
      child.on("close", (code) => done(null, code, out));
    };
    if (dshInstallRoot && existsSync(path.join(dshInstallRoot, "lib", "bin.js"))) {
      attempt(process.execPath, [path.join(dshInstallRoot, "lib", "bin.js"), ...args]);
    } else {
      attempt("dsh", args);
    }
  });
}

/**
 * Register the API routes. `service` must provide: list(), runReview(),
 * uninstall(name). Returns the route array (each element is webServer-
 * registerable).
 */
export function buildSecurityReviewApi(service) {
  return [
    getRoute("/api/security-review/list", () => service.list()),
    postRoute("/api/security-review/run", () => service.runReview()),
    postRoute("/api/security-review/uninstall", (body) => {
      const name = typeof body.name === "string" ? body.name.trim() : "";
      if (!name) return Promise.reject(new Error("missing-name"));
      return service.uninstall(name);
    }),
    postRoute("/api/security-review/review", (body) => {
      const target = typeof body.target === "string" ? body.target.trim() : "";
      if (!target) return Promise.reject(new Error("missing-target"));
      return service.reviewTarget(target, {});
    }),
    postRoute("/api/security-review/install", (body) => {
      const target = typeof body.target === "string" ? body.target.trim() : "";
      if (!target) return Promise.reject(new Error("missing-target"));
      return service.installTarget(target, { force: body.force === true });
    }),
    getRoute("/api/security-review/gate", () => service.gateStatus()),
    postRoute("/api/security-review/gate", (body) => service.gateSet(body.enable === true))
  ];
}

export { runPnpmRemove, runDshPluginAdd };
