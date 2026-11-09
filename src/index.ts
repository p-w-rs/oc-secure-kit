/** Version of the secure-kit API, so plugins can report which vendored copy they run. */
export const SECURE_KIT_VERSION = "0.1.0"

/** On-disk format identifiers. Bumping one requires a migration in the owning module. */
export const FORMATS = {
  vault: "oc-vault/1",
  bundle: "oc-bundle/1",
} as const
