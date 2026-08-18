import { createHash } from "node:crypto";

/**
 * Shared small helpers for the static analyzer. No dsh/cordis imports: the
 * analyzer must also run standalone inside the CLI.
 */

/** Normalize a path for display (always forward slashes). */
export function displayPath(p) {
  return String(p).replace(/\\/g, "/");
}

/** True when a path basename or dir matches a skip rule. */
export function isSkippableDir(name) {
  return (
    name === "node_modules" ||
    name === ".git" ||
    name === ".hg" ||
    name === ".svn" ||
    name === ".pnpm-store" ||
    name === "__MACOSX"
  );
}

/** 1-based line number of an index inside text. */
export function lineOf(text, index) {
  let line = 1;
  const cap = Math.min(index, text.length);
  for (let i = 0; i < cap; i++) if (text.charCodeAt(i) === 10) line += 1;
  return line;
}

/** Short code snippet around an index, trimmed to one readable line. */
export function snippetOf(text, index, maxLen = 160) {
  const start = Math.max(0, index - 40);
  const end = Math.min(text.length, index + maxLen);
  let snippet = text.slice(start, end).replace(/\s+/g, " ").trim();
  if (snippet.length > maxLen) snippet = snippet.slice(0, maxLen) + "...";
  return snippet;
}

/** Hex sha1 of a string (cache keys, anonymous ids). */
export function sha1Hex(input) {
  return createHash("sha1").update(input).digest("hex");
}

/** Base64 sha512 of a buffer (integrity verification of registry tarballs). */
export function sha512B64(buffer) {
  return createHash("sha512").update(buffer).digest("base64");
}

/** Loose check whether a string looks base64-encoded. */
export function looksLikeBase64(text) {
  return /^[A-Za-z0-9+\/]+={0,2}$/.test(text) && text.length >= 24;
}

/** Count occurrences of a regex in text. */
export function countMatches(re, text) {
  re.lastIndex = 0;
  let n = 0;
  let m;
  while ((m = re.exec(text)) !== null) n += 1;
  return n;
}

/** Truncate a string safely. */
export function clip(text, max = 500) {
  return text.length <= max ? text : text.slice(0, max) + "...";
}

/** Best-effort parse of a name@range into { name, range }. */
export function splitPackageSpec(spec) {
  const raw = String(spec || "").trim();
  if (raw.startsWith("@")) {
    const at = raw.indexOf("@", 1);
    if (at === -1) return { name: raw, range: undefined };
    return { name: raw.slice(0, at), range: raw.slice(at + 1) };
  }
  const at = raw.lastIndexOf("@");
  if (at <= 0) return { name: raw, range: undefined };
  return { name: raw.slice(0, at), range: raw.slice(at + 1) };
}
