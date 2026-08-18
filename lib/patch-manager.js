import path from "node:path";
import { existsSync, readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";

export const MANAGED_BEGIN = "# --- security-review managed block (auto-generated, do not edit) ---";
export const MANAGED_END = "# --- end security-review managed block ---";

/**
 * Line-based editor for the managed `disabled: true` block inside a
 * profile's cordis.patch.yml. The rest of the user's file (comments,
 * formatting, custom rows) is preserved verbatim: only the block between
 * the markers is regenerated.
 */
export class ManagedPatch {
  constructor(profileDir) {
    this.file = path.join(profileDir, "cordis.patch.yml");
  }

  read() {
    if (!existsSync(this.file)) return "";
    return readFileSync(this.file, "utf8");
  }

  /** Ids currently managed by the block. */
  managedIds() {
    const text = this.read();
    const lines = text.split(/\r?\n/);
    const ids = [];
    let inside = false;
    for (const line of lines) {
      if (line.trim() === MANAGED_BEGIN) { inside = true; continue; }
      if (line.trim() === MANAGED_END) { inside = false; continue; }
      if (!inside) continue;
      const m = /^\s*-\s+id:\s*("?)([^"\s]+)\1\s*$/.exec(line);
      if (m) ids.push(m[2]);
    }
    return ids;
  }

  /**
   * Regenerate the managed block so it holds exactly `ids` (each row
   * disabled). Returns true when the file changed on disk.
   */
  sync(ids) {
    const wanted = [...new Set(ids)].sort();
    const before = this.read();
    const lines = before.split(/\r?\n/);
    const start = lines.findIndex((line) => line.trim() === MANAGED_BEGIN);
    const end = lines.findIndex((line) => line.trim() === MANAGED_END);
    const block = [MANAGED_BEGIN];
    for (const id of wanted) {
      block.push("- id: " + JSON.stringify(id));
      block.push("  disabled: true");
    }
    block.push(MANAGED_END);
    let out;
    if (start !== -1 && end !== -1 && end > start) {
      out = [...lines.slice(0, start), ...block, ...lines.slice(end + 1)];
    } else {
      const body = lines.filter((line) => line.trim() !== "");
      out = [...body, ...block];
    }
    const after = out.join("\n").replace(/\n+$/, "") + "\n";
    if (after === before) return false;
    mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = this.file + ".tmp-" + process.pid + "-" + Date.now();
    writeFileSync(tmp, after, "utf8");
    renameSync(tmp, this.file);
    return true;
  }
}
