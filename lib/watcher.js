import { watch, existsSync, readFileSync } from "node:fs";
import path from "node:path";

/**
 * Read a profile's package.json dependencies as an object.
 */
export function readProfileDeps(profileDir) {
  const file = path.join(profileDir, "package.json");
  if (!existsSync(file)) return {};
  try {
    const pkg = JSON.parse(readFileSync(file, "utf8"));
    return pkg && typeof pkg.dependencies === "object" ? pkg.dependencies : {};
  } catch {
    return {};
  }
}

/**
 * Watch a profile's package.json for dependency changes (installs /
 * upgrades / removals) and notify via `onChanged({ added, changed, removed })`.
 *
 * Uses fs.watch for immediacy plus a low-frequency poll fallback because
 * pnpm rewrites package.json via rename, which can drop change events on
 * some platforms. Dependencies are diffed by name (added/removed) and by
 * version range (changed); all three are forwarded.
 *
 * Returns a handle with `.close()`.
 */
export function startInstallWatcher({ profileDir, onChanged, debounceMs = 800, pollMs = 5000 }) {
  if (!profileDir) return { close() {} };
  const pkgJson = path.join(profileDir, "package.json");
  let lastDeps = readProfileDeps(profileDir);
  let timer = null;
  let closed = false;
  let fsWatcher = null;

  const diff = () => {
    if (closed) return;
    const now = readProfileDeps(profileDir);
    const added = [];
    const changed = [];
    for (const [k, v] of Object.entries(now)) {
      if (!(k in lastDeps)) added.push(k);
      else if (lastDeps[k] !== v) changed.push(k);
    }
    const removed = Object.keys(lastDeps).filter((k) => !(k in now));
    lastDeps = now;
    if (!added.length && !changed.length && !removed.length) return;
    try { onChanged({ added, changed, removed }); } catch (error) {
      console.error("[security-review] install watcher callback failed: " + (error?.message ?? String(error)));
    }
  };

  const schedule = () => {
    if (closed) return;
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => { timer = null; diff(); }, debounceMs);
  };

  try {
    // Watch the directory: pnpm may replace package.json via rename, which
    // a file watcher can miss; a directory watcher catches rename + change.
    fsWatcher = watch(profileDir, (_event, filename) => {
      if (filename === "package.json") schedule();
    });
    fsWatcher.on("error", () => {});
  } catch {
    // fs.watch unavailable — poll fallback still works
  }

  const poll = setInterval(schedule, pollMs);

  return {
    close() {
      closed = true;
      if (timer) clearTimeout(timer);
      clearInterval(poll);
      try { fsWatcher?.close(); } catch {}
    }
  };
}
