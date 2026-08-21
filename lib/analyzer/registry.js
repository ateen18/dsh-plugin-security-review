import { splitPackageSpec } from "./util.js";
import { selectVersion } from "./semver.js";
import { sha512B64 } from "./util.js";

export const DEFAULT_REGISTRY = "https://registry.npmjs.org";

/**
 * Classify an install/review spec into one review pipeline:
 * registry | git | url | file
 */
export function classifySpec(spec) {
  const raw = String(spec || "").trim();
  if (/^file:/i.test(raw) || /^link:/i.test(raw) || /^\.\.?[\/\\]/.test(raw) || /^[A-Za-z]:[\/\\]/.test(raw)) return "file";
  if (/^https?:\/\/\S+\.(?:tgz|tar\.gz)$/i.test(raw)) return "url";
  if (/^git\+/.test(raw) || /^git@/.test(raw) || /^github:/i.test(raw) || /\.git(?:#.*)?$/.test(raw)) return "git";
  // 常见 git 托管平台的 https URL（owner/repo 两段路径，可带或不带 .git 后缀）视为 git，
  // 避免被误判为 npm 包名
  if (/^https?:\/\/(?:www\.)?(?:github\.com|gitlab\.com|gitee\.com|bitbucket\.org|gitcode\.com|atomgit\.com)\/[^\/\s]+\/[^\/\s]+(?:\/|\.git(?:#.*)?)?$/i.test(raw)) return "git";
  return "registry";
}

/**
 * Normalize a git spec into a form pnpm accepts on `add`:
 *   https://github.com/owner/repo(.git)  ->  github:owner/repo
 * Other git/url specs pass through unchanged.
 */
export function normalizeGitSpecForPnpm(spec) {
  const raw = String(spec || "").trim();
  const m = /^https?:\/\/(?:www\.)?github\.com\/([^\/\s]+)\/([^\/\s#]+)/i.exec(raw);
  if (m) return "github:" + m[1] + "/" + m[2].replace(/\.git$/i, "");
  return raw;
}

/**
 * Fetch registry metadata for a package name. Returns the parsed JSON
 * document or throws.
 */
export async function fetchRegistryMeta(name, registry = DEFAULT_REGISTRY) {
  const url = registry.replace(/\/$/, "") + "/" + encodeURIComponent(name);
  const response = await fetch(url, {
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(30000)
  });
  if (!response.ok) throw new Error("registry lookup failed for " + name + ": HTTP " + response.status);
  const doc = await response.json();
  if (doc.error) throw new Error("registry lookup failed for " + name + ": " + String(doc.error));
  return doc;
}

/**
 * Resolve a registry spec to { name, version, tarballUrl, integrity }.
 */
export async function resolveRegistrySpec(spec, registry = DEFAULT_REGISTRY) {
  const { name, range } = splitPackageSpec(spec);
  if (!name) throw new Error("invalid package spec: " + spec);
  const doc = await fetchRegistryMeta(name, registry);
  const versions = Object.keys(doc.versions ?? {});
  let version;
  let note;
  if (range) {
    const selected = selectVersion(versions, range);
    if (!selected || !selected.version) {
      const dist = doc["dist-tags"] ?? {};
      version = dist[range] ?? dist.latest;
      note = "版本范围 " + range + " 无法精确解析，回退到 " + (version ?? "latest");
    } else {
      version = selected.version;
    }
  } else {
    version = (doc["dist-tags"] ?? {}).latest;
  }
  const entry = doc.versions?.[version];
  if (!entry) throw new Error("version " + version + " of " + name + " not found in registry");
  return {
    name,
    version,
    tarballUrl: entry.dist?.tarball,
    integrity: entry.dist?.integrity,
    shasum: entry.dist?.shasum,
    note,
    meta: {
      description: entry.description,
      license: entry.license,
      repository: entry.repository,
      homepage: entry.homepage,
      author: entry.author,
      time: doc.time?.[version],
      modified: doc.time?.modified
    }
  };
}

/**
 * Download a tarball with a size cap and optional sha512 integrity check.
 * Returns { buffer, integrityOk }.
 */
export async function downloadTarball(url, opts = {}) {
  if (!url) throw new Error("registry entry has no tarball url");
  const maxBytes = opts.maxBytes ?? 100 * 1024 * 1024;
  const response = await fetch(url, {
    redirect: "follow",
    signal: AbortSignal.timeout(opts.timeoutMs ?? 120000)
  });
  if (!response.ok) throw new Error("tarball download failed: HTTP " + response.status + " " + url);
  const length = Number(response.headers.get("content-length"));
  if (Number.isFinite(length) && length > maxBytes) throw new Error("tarball too large: " + length + " bytes");
  const buffer = Buffer.from(await response.arrayBuffer());
  if (buffer.length > maxBytes) throw new Error("tarball too large: " + buffer.length + " bytes");
  let integrityOk = false;
  if (opts.integrity && /^sha512-/.test(opts.integrity)) {
    integrityOk = "sha512-" + sha512B64(buffer) === opts.integrity;
  } else if (opts.shasum && /^[0-9a-f]{40}$/i.test(opts.shasum)) {
    const { createHash } = await import("node:crypto");
    integrityOk = createHash("sha1").update(buffer).digest("hex") === String(opts.shasum).toLowerCase();
  }
  return { buffer, integrityOk, bytes: buffer.length };
}
