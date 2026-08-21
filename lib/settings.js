import { hostImport } from "./host.js";

export const SETTINGS_NS = "security-review";

/**
 * Settings schema. policy is a plain string on purpose (clamped in
 * validate) so an unknown stored value can never break registration.
 * `z` is the schemastery instance provided by the caller (from the host
 * dsh installation), so the schema classes match the host's settings
 * system.
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

/**
 * Clamp a resolved settings section into the policy shape the gate uses.
 */
export function normalizePolicy(section) {
  const mode = ["standard", "strict", "audit-only"].includes(section?.policy) ? section.policy : "standard";
  return {
    mode,
    autoDisable: section?.autoDisable === true,
    autoPatchProfile: section?.autoPatchProfile === true,
    installGate: section?.installGate === true,
    runtimeGuard: ["off", "log", "block"].includes(section?.runtimeGuard) ? section.runtimeGuard : "off",
    allowlist: Array.isArray(section?.allowlist) ? section.allowlist.map(String) : []
  };
}

/**
 * Wire the canonical optional-settings consumer. Returns a thunk that
 * yields the current resolved policy. Host packages are imported lazily
 * from the running dsh installation (see host.js) — the schemastery fork
 * the host uses is `@deepseek-ai/schemastery`, not the unscoped package.
 */
export async function registerSettings(ctx, entryConfig, onChange) {
  const [zModule, settingsModule] = await Promise.all([
    hostImport("@deepseek-ai/schemastery"),
    hostImport("@deepseek-ai/dsh-settings")
  ]);
  const z = zModule.default ?? zModule;
  const { installSettingsSection, settingsNamespace } = settingsModule;
  const policy = normalizePolicy(entryConfig ?? {});
  const base = { policy: policy.mode, autoDisable: policy.autoDisable, autoPatchProfile: policy.autoPatchProfile, installGate: policy.installGate, runtimeGuard: policy.runtimeGuard, allowlist: policy.allowlist };
  let current = () => base;
  installSettingsSection(ctx, settingsNamespace(SETTINGS_NS), makeSettingsSchema(z), base, {
    setSource: (source) => { current = source; },
    onChange: () => {
      const policy = normalizePolicy(current());
      onChange(policy);
    },
    validate: (value) => {
      if (value && typeof value.policy === "string" && !["standard", "strict", "audit-only"].includes(value.policy)) {
        throw new Error("policy 必须是 standard / strict / audit-only 之一");
      }
    }
  });
  return () => normalizePolicy(current());
}
