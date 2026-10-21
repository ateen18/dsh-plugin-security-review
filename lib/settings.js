import path from "node:path";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { hostImport } from "./host.js";
import { resolveDshHome } from "./store.js";

export const SETTINGS_NS = "security-review";

/**
 * 设置面。
 *
 * 0.1.x（web 版 dsh）提供 `installSettingsSection`，把 schema 交给宿主的设置页；
 * 0.2.x（桌面客户端的运行时）删掉了这个导出，改为“条目 Config + settings 文档”
 * 的模型。为了同时支持两代运行时，这里：
 *
 *   1. 始终维护一份自有的持久化策略（`$DSH_HOME/security-review/settings.json`），
 *      它是插件真正的策略来源，web 和桌面表现一致；
 *   2. 如果能解析到 0.1.x 的 `installSettingsSection`，额外把 schema 挂进宿主
 *      设置页（web 老版本行为不变）；
 *   3. 两代运行时都通过插件自己的设置分区（`/api/security-review/settings`）编辑，
 *      保存后立即作用到门禁，无需重启。
 *
 * `z` 由宿主提供（`@deepseek-ai/schemastery`），保证 schema 类与宿主一致。
 */
export function makeSettingsSchema(z) {
  return z.object({
    policy: z.string().default("standard"),
    autoDisable: z.boolean().default(false),
    autoPatchProfile: z.boolean().default(false),
    installGate: z.boolean().default(false),
    runtimeGuard: z.string().default("off"),
    allowlist: z.array(z.string()).default([])
  });
}

/** 设置文件的绝对路径（root 缺省为 `$DSH_HOME/security-review`）。 */
export function settingsFilePath(root) {
  return path.join(root ?? path.join(resolveDshHome(), "security-review"), "settings.json");
}

/**
 * 读取已持久化的策略片段；文件损坏或缺失时返回 `{}`（fail-open，不阻断启动）。
 */
export function loadStoredSettings(root) {
  const file = settingsFilePath(root);
  try {
    if (!existsSync(file)) return {};
    const parsed = JSON.parse(readFileSync(file, "utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

/**
 * 原子写入策略片段。
 * @returns 实际写入的文件路径。
 */
export function saveStoredSettings(root, value) {
  const file = settingsFilePath(root);
  mkdirSync(path.dirname(file), { recursive: true });
  const temp = file + ".tmp-" + process.pid;
  writeFileSync(temp, JSON.stringify(value, null, 2) + "\n", "utf8");
  renameSync(temp, file);
  return file;
}

/**
 * 把一条策略（含内部 `mode` 字段）还原成设置面的形状。
 */
export function policyToSettings(policy) {
  return {
    policy: policy?.mode ?? "standard",
    autoDisable: policy?.autoDisable === true,
    autoPatchProfile: policy?.autoPatchProfile === true,
    installGate: policy?.installGate === true,
    runtimeGuard: policy?.runtimeGuard ?? "off",
    allowlist: Array.isArray(policy?.allowlist) ? [...policy.allowlist] : []
  };
}

/**
 * 只保留已知字段并做取值收敛，避免客户端提交任意键污染策略。
 */
export function sanitizeSettings(input) {
  const value = input && typeof input === "object" ? input : {};
  const policy = ["standard", "strict", "audit-only"].includes(value.policy) ? value.policy : "standard";
  return {
    policy,
    autoDisable: value.autoDisable === true,
    autoPatchProfile: value.autoPatchProfile === true,
    installGate: value.installGate === true,
    runtimeGuard: ["off", "log", "block"].includes(value.runtimeGuard) ? value.runtimeGuard : "off",
    allowlist: Array.isArray(value.allowlist) ? value.allowlist.map(String).filter(Boolean).slice(0, 500) : []
  };
}

/**
 * 把设置面 / 条目 config 收敛成门禁使用的策略形状。
 */
export function normalizePolicy(section) {
  const settings = sanitizeSettings(section && section.policy === undefined && section.mode !== undefined
    ? policyToSettings(section)
    : section);
  return {
    mode: settings.policy,
    autoDisable: settings.autoDisable,
    autoPatchProfile: settings.autoPatchProfile,
    installGate: settings.installGate,
    runtimeGuard: settings.runtimeGuard,
    allowlist: settings.allowlist
  };
}

/**
 * 接线设置。条目 config 提供缺省值，持久化文件覆盖它，宿主设置页（0.1.x）
 * 的改动也会被吸收进来。
 *
 * @param ctx - 宿主上下文。
 * @param entryConfig - profile 补丁里给本条目写的 config。
 * @param onChange - 策略变化回调。
 * @returns `{getPolicy, getSettings, update}`：读当前策略 / 读设置面 / 应用并持久化。
 */
export async function registerSettings(ctx, entryConfig, onChange) {
  const base = sanitizeSettings(entryConfig);
  const stored = sanitizeSettings({ ...base, ...loadStoredSettings() });
  let current = stored;

  const apply = (next, { persist }) => {
    current = sanitizeSettings(next);
    if (persist) {
      try {
        saveStoredSettings(undefined, current);
      } catch (error) {
        console.error("[security-review] 策略持久化失败:", error?.message ?? error);
      }
    }
    onChange(normalizePolicy(current));
    return current;
  };

  // 0.1.x 的宿主设置页接线（导出不存在时静默跳过——0.2.x 桌面运行时就是这种）。
  try {
    const [zModule, settingsModule] = await Promise.all([
      hostImport("@deepseek-ai/schemastery"),
      hostImport("@deepseek-ai/dsh-settings")
    ]);
    const { installSettingsSection, settingsNamespace } = settingsModule ?? {};
    if (typeof installSettingsSection !== "function" || typeof settingsNamespace !== "function") {
      throw new Error("host settings API unavailable");
    }
    const z = zModule.default ?? zModule;
    installSettingsSection(ctx, settingsNamespace(SETTINGS_NS), makeSettingsSchema(z), current, {
      setSource: (source) => {
        try {
          current = sanitizeSettings({ ...current, ...source() });
        } catch {}
      },
      onChange: () => {
        onChange(normalizePolicy(current));
      },
      validate: (value) => {
        if (value && typeof value.policy === "string" && !["standard", "strict", "audit-only"].includes(value.policy)) {
          throw new Error("policy 必须是 standard / strict / audit-only 之一");
        }
      }
    });
  } catch {
    // 0.2.x/桌面：宿主不再提供 installSettingsSection，策略由本插件自己的设置分区编辑。
  }

  return {
    getPolicy: () => normalizePolicy(current),
    getSettings: () => current,
    update: (patch) => apply({ ...current, ...(patch ?? {}) }, { persist: true })
  };
}
