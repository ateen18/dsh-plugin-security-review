import { gunzipSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

/**
 * Minimal tar (ustar + GNU longname + PAX) extractor, dependency-free.
 * Only used by the CLI for registry/tarball review: extract into a temp
 * directory with size and path-safety caps. Symlinks are recorded but
 * never created; devices are refused.
 */
const BLOCK = 512;

function octalField(buf, start, len) {
  let end = start + len;
  while (end > start && (buf[end - 1] === 0 || buf[end - 1] === 32)) end -= 1;
  const text = buf.toString("utf8", start, end).trim();
  if (!text) return 0;
  const n = parseInt(text, 8);
  return Number.isFinite(n) ? n : 0;
}

function parsePaxRecords(block) {
  const text = block.toString("utf8");
  const end = text.indexOf("\0");
  const body = (end === -1 ? text : text.slice(0, end)).trim();
  const records = {};
  let i = 0;
  while (i < body.length) {
    const sp = body.indexOf(" ", i);
    if (sp === -1) break;
    const len = parseInt(body.slice(i, sp), 10);
    if (!Number.isFinite(len) || len <= 0) break;
    const record = body.slice(sp + 1, i + len);
    const eq = record.indexOf("=");
    if (eq !== -1) {
      const key = record.slice(0, eq);
      const value = record.slice(eq + 1);
      records[key] = value.replace(/\n$/, "");
    }
    i += len;
  }
  return records;
}

function safeJoin(dest, name) {
  const normalized = name.replace(/\\/g, "/").replace(/^\/+/, "");
  const parts = [];
  for (const part of normalized.split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") {
      if (parts.length === 0) throw new Error("tar path escapes destination");
      parts.pop();
      continue;
    }
    parts.push(part);
  }
  const out = path.join(dest, ...parts);
  const rel = path.relative(dest, out);
  if (rel.startsWith("..") || path.isAbsolute(rel)) throw new Error("tar path escapes destination");
  return out;
}

/**
 * Extract a .tar.gz buffer into destDir.
 * Returns { files, symlinks, warnings } (files = absolute paths).
 */
export function extractTgz(buffer, destDir, opts = {}) {
  const maxTotalBytes = opts.maxTotalBytes ?? 300 * 1024 * 1024;
  const maxFiles = opts.maxFiles ?? 20000;
  const tar = gunzipSync(buffer);
  const files = [];
  const symlinks = [];
  const warnings = [];
  let total = 0;
  let offset = 0;
  let pendingName = null;
  let pax = null;
  while (offset + BLOCK <= tar.length) {
    const header = tar.subarray(offset, offset + BLOCK);
    if (header.every((b) => b === 0)) {
      offset += BLOCK;
      continue;
    }
    let name = header.toString("utf8", 0, 100).replace(/\0.*$/, "");
    const size = octalField(header, 124, 12);
    const type = String.fromCharCode(header[156] ?? 0);
    let linkname = header.toString("utf8", 157, 100).replace(/\0.*$/, "");
    const magic = header.toString("utf8", 257, 6);
    if (magic !== "ustar ") {
      warnings.push("non-ustar header block ignored");
      break;
    }
    const dataStart = offset + BLOCK;
    const dataEnd = dataStart + Math.ceil(size / BLOCK) * BLOCK;
    if (dataEnd > tar.length) {
      warnings.push("truncated entry: " + name);
      break;
    }
    const data = tar.subarray(dataStart, dataStart + size);
    if (type === "L") {
      pendingName = data.toString("utf8").replace(/\0.*$/, "");
    } else if (type === "g" || type === "x") {
      const records = parsePaxRecords(data);
      pax = { ...(pax ?? {}), ...records };
    } else {
      if (pendingName) { name = pendingName; pendingName = null; }
      if (pax) {
        if (pax.path) name = pax.path;
        if (pax.linkpath) linkname = pax.linkpath;
        pax = null;
      }
      if (type === "0" || type === "\0" || type === "7" || type === "") {
        let out;
        try {
          out = safeJoin(destDir, name);
        } catch (error) {
          warnings.push(String(error?.message ?? error));
          offset = dataEnd;
          continue;
        }
        total += size;
        if (total > maxTotalBytes) throw new Error("tarball exceeds extraction size cap");
        if (files.length >= maxFiles) throw new Error("tarball exceeds file count cap");
        try {
          mkdirSync(path.dirname(out), { recursive: true });
          writeFileSync(out, data);
          files.push(out);
        } catch (error) {
          warnings.push("write failed for " + name + ": " + String(error?.message ?? error));
        }
      } else if (type === "5") {
        try {
          mkdirSync(safeJoin(destDir, name), { recursive: true });
        } catch (error) {
          warnings.push("mkdir failed for " + name + ": " + String(error?.message ?? error));
        }
      } else if (type === "2") {
        symlinks.push({ name, linkname });
      } else {
        warnings.push("skipped unsupported tar entry type " + JSON.stringify(type) + " for " + name);
      }
    }
    offset = dataEnd;
  }
  return { files, symlinks, warnings };
}

export { safeJoin };
