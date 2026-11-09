/** Version of the secure-kit API, so plugins can report which vendored copy they run. */
export const SECURE_KIT_VERSION = "0.4.1"

export { BUNDLE_FORMAT, DEFAULT_COST, MIN_PASSPHRASE_LENGTH, decryptBundle, diffRecords, encryptBundle, inspectBundle } from "./bundle.js"
export type { BundleEnvelope, BundleHeader, DiffItem, DiffStatus, KdfParams, Migrations } from "./bundle.js"
export { PermissionBridge, guardDirectories, sessionRoots } from "./bridge.js"
export type { AssertInput, CheckInput, EvaluateEvent, EventHost, ParentLookup, PermissionEvent, PermissionHost, Registration } from "./bridge.js"
export { Serial, atomicWrite, ensurePrivateDir, pluginDataDir, readJson, withFileLock } from "./fsutil.js"
export { EFFECTS, POLICY_FORMAT, PolicyStore, StaleRevisionError, combineEffects, resolveEffect } from "./policy.js"
export type { AgentRows, CellChange, Effect, EntityPolicy, PolicyDoc, Resolution, ResolveInput, Row, SessionOverride } from "./policy.js"
export { MIN_SECRET_LENGTH, Redactor, installRedaction, patternsFor } from "./redact.js"
export type { Pattern, ToolHookHost } from "./redact.js"
export { SecretRequests, cleanText } from "./requests.js"
export type { SecretRequest } from "./requests.js"
export { MAX_SECRET_BYTES, VAULT_FORMAT, Vault, fileKey, memoryKey, validName } from "./vault.js"
export type { KeySource, SecretMeta, SecretValue } from "./vault.js"

/** On-disk format identifiers. Bumping one requires a migration in the owning module. */
export const FORMATS = {
  vault: "oc-vault/1",
  policy: "oc-policy/1",
  bundle: "oc-bundle/1",
  requests: "oc-requests/1",
} as const
