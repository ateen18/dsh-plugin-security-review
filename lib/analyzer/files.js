import { readFileSync, statSync, existsSync } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { isSkippableDir } from "./util.js";

export const DEFAULT_CAPS = {
  maxFiles: 5000,
  maxFileBytes: 2 * 1024 * 1024,
  maxTotalBytes: 200 * 1024 * 1024,
  maxDepth: 24
};

/** Extensions treated as opaque binary artifacts (flagged, not scanned). */
export const BINARY_EXTS = new Set([".node", ".exe", ".dll", ".so", ".dylib", ".bin", ".wasm"]);

/**
 * Path patterns skipped by default when scanning a package.
 * - trailing "/" marks a directory name, matched on whole path segments
 *   (so "test/" does NOT match "latest/")
 * - "*.ext" marks a file suffix
 * Rationale: test fixtures intentionally contain dangerous-looking samples
 * used to exercise the analyzer itself; they are not shipped runtime code.
 * Set caps.defaultIgnore = false to scan everything (strict mode).
 */
export const DEFAULT_IGNORE = [
  "test/", "tests/", "__tests__/", "fixtures/", "coverage/",
  "*.test.js", "*.test.mjs", "*.test.cjs", "*.spec.js", "*.spec.mjs"
];

/** Segment-anchored ignore pattern matching. */
export function matchesIgnore(rel, patterns) {
  for (const p of patterns) {
    if (p.endsWith("/")) {
      const dir = p.slice(0, -1);
      if (rel === dir || rel.startsWith(dir + "/") || rel.includes("/" + dir + "/")) return true;
    } else if (p.startsWith("*.")) {
      if (rel.endsWith(p.slice(1))) return true;
    } else if (rel === p || rel.endsWith("/" + p)) {
      return true;
    }
  }
  return false;
}

/** Extensions scanned as source text. */
export const TEXT_EXTS = new Set([
  ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx",
  ".json", ".yml", ".yaml", ".md", ".html", ".htm", ".css", ".scss",
  ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".py", ".rb", ".pl",
  ".lua", ".go", ".rs", ".c", ".h", ".cpp", ".hpp", ".java", ".kt",
  ".vue", ".svelte", ".xml", ".toml", ".ini", ".conf", ".txt", ".lock"
]);

/**
 * Recursively collect files under root with size/count caps.
 * Returns { files, skipped, binary, totalBytes, dirs }.
 */
export async function collectFiles(root, caps = {}) {
  const c = { ...DEFAULT_CAPS, ...caps };
  const ignore = c.defaultIgnore === false ? (c.ignore ?? []) : [...DEFAULT_IGNORE, ...(c.ignore ?? [])];
  const files = [];
  const skipped = [];
  const binary = [];
  let totalBytes = 0;
  let dirs = 0;
  const walk = async (dir, depth) => {
    if (depth > c.maxDepth) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    dirs += 1;
    for (const entry of entries) {
      if (files.length + skipped.length >= c.maxFiles * 4) {
        skipped.push({ rel: entry.name, reason: "file-count-cap" });
        continue;
      }
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (isSkippableDir(entry.name)) continue;
        await walk(abs, depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;
      let size = 0;
      try { size = statSync(abs).size; } catch { continue; }
      totalBytes += size;
      const rel = path.relative(root, abs).replace(/\\/g, "/");
      const ext = path.extname(entry.name).toLowerCase();
      if (matchesIgnore(rel, ignore)) {
        skipped.push({ rel, reason: "ignored-pattern" });
        continue;
      }
      if (BINARY_EXTS.has(ext)) {
        binary.push({ rel, bytes: size });
        continue;
      }
      if (size > c.maxFileBytes) {
        skipped.push({ rel, reason: "too-large", bytes: size });
        continue;
      }
      if (totalBytes > c.maxTotalBytes) {
        skipped.push({ rel, reason: "total-cap" });
        continue;
      }
      files.push({ abs, rel: rel.replace(/\\/g, "/"), bytes: size, ext });
      if (files.length >= c.maxFiles) return;
    }
  };
  await walk(root, 0);
  return { files, skipped, binary, totalBytes, dirs };
}

/** Read a text file, detecting binary content via a NUL byte in the head. */
export function readTextFile(abs, maxBytes = DEFAULT_CAPS.maxFileBytes) {
  const buf = readFileSync(abs);
  const head = buf.subarray(0, Math.min(8192, buf.length));
  for (let i = 0; i < head.length; i++) if (head[i] === 0) return null;
  return buf.toString("utf8", 0, Math.min(buf.length, maxBytes));
}

/** Nearest package.json walking up from a file path; null when none. */
export function findPackageJson(filePath) {
  let dir = path.dirname(filePath);
  for (let i = 0; i < 40; i++) {
    const candidate = path.join(dir, "package.json");
    if (existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
  return null;
}

/** Read + parse a package.json; null when missing or unparsable. */
export function readPackageJson(dir) {
  const file = path.join(dir, "package.json");
  if (!existsSync(file)) return null;
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}
