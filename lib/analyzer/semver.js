/**
 * Minimal semver helpers — enough for common install specs (exact, ^, ~, >=,
 * <=, >, <, x-ranges). Anything unsupported resolves to the latest version
 * with a note. No external dependencies.
 */

export function parseVersion(input) {
  const m = /^v?(\d+)(?:\.(\d+|x|X|\*))?(?:\.(\d+|x|X|\*))?(?:-([0-9A-Za-z.-]+))?/.exec(String(input || "").trim());
  if (!m) return null;
  const part = (s) => (s === undefined || s === "x" || s === "X" || s === "*" ? null : Number(s));
  return { major: part(m[1]), minor: part(m[2]), patch: part(m[3]), prerelease: m[4] ?? null };
}

/** Compare two parsed versions (prerelease < release). */
export function compareVersions(a, b) {
  for (const key of ["major", "minor", "patch"]) {
    const x = a[key] === null ? 0 : a[key];
    const y = b[key] === null ? 0 : b[key];
    if (x !== y) return x > y ? 1 : -1;
  }
  if (!a.prerelease && !b.prerelease) return 0;
  if (!a.prerelease) return 1;
  if (!b.prerelease) return -1;
  return a.prerelease < b.prerelease ? -1 : a.prerelease > b.prerelease ? 1 : 0;
}

function bump(version, index) {
  const out = { ...version };
  const keys = ["major", "minor", "patch"];
  const key = keys[index];
  out[key] = (out[key] ?? 0) + 1;
  for (let i = index + 1; i < keys.length; i++) out[keys[i]] = 0;
  out.prerelease = null;
  return out;
}

function compareTarget(target, version) {
  if (target.major !== version.major) return target.major > version.major;
  if (target.minor === null) return true;
  if (target.minor !== version.minor) return target.minor > version.minor;
  if (target.patch === null) return true;
  return target.patch >= version.patch;
}

/**
 * Test a single simple range clause against a version string.
 * Returns true/false, or null when the clause is unsupported.
 */
export function satisfiesClause(clause, versionString) {
  const raw = String(clause || "").trim();
  if (!raw || raw === "*" || raw === "latest" || raw === "x") return true;
  const version = parseVersion(versionString);
  if (!version) return null;
  let m = /^\^(.*)$/.exec(raw);
  if (m) {
    const base = parseVersion(m[1]);
    if (!base) return null;
    const upper = bump(base, base.major > 0 ? 0 : base.minor > 0 ? 1 : 2);
    return compareVersions(version, base) >= 0 && compareVersions(version, upper) < 0;
  }
  m = /^~([^\s]+)$/.exec(raw);
  if (m) {
    const base = parseVersion(m[1]);
    if (!base) return null;
    const upper = bump(base, base.minor === null ? 0 : 1);
    return compareVersions(version, base) >= 0 && compareVersions(version, upper) < 0;
  }
  m = /^>=?\s*(.*)$/.exec(raw);
  if (m) {
    const base = parseVersion(m[1]);
    if (!base) return null;
    const cmp = compareVersions(version, base);
    return raw.startsWith(">=") ? cmp >= 0 : cmp > 0;
  }
  m = /^<=?\s*(.*)$/.exec(raw);
  if (m) {
    const base = parseVersion(m[1]);
    if (!base) return null;
    const cmp = compareVersions(version, base);
    return raw.startsWith("<=") ? cmp <= 0 : cmp < 0;
  }
  const base = parseVersion(raw);
  if (!base) return null;
  return compareTarget(base, version);
}

/**
 * Pick the best matching version for a range from a list of version strings.
 * Returns { version, exact } or null when nothing matches.
 */
export function selectVersion(versions, range) {
  const list = [...versions].sort((a, b) => compareVersions(parseVersion(b), parseVersion(a)));
  const clause = String(range || "").trim();
  if (!clause || clause === "latest" || clause === "*") return { version: list[0] ?? null, exact: false };
  let best = null;
  let matched = false;
  for (const v of list) {
    const ok = satisfiesClause(clause, v);
    if (ok === null) return null; // unsupported range syntax
    if (ok) {
      best = v;
      matched = true;
      break;
    }
  }
  return best ? { version: best, exact: matched && /^\d/.test(clause) && !/[<>=~^]/.test(clause) } : null;
}
