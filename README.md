# secure-kit

Shared building blocks for the `oc-*` OpenCode plugins. Node built-ins only;
macOS and Linux. This is a library, not a plugin: each plugin vendors a packed
tarball so it builds from its own folder.

```sh
pixi run --locked test     # typecheck + tests
pixi run --locked pack     # -> .local/pack/oc-secure-kit-<version>.tgz (+ sha256)
```

Then in a plugin: `pixi run vendor-kit ../secure-kit/.local/pack/oc-secure-kit-<version>.tgz && pixi run deps-update`.

## Modules

| Module | What it provides |
|---|---|
| `vault` | `Vault`: AES-256-GCM per secret, bound to `(plugin, entity, name)` as associated data. `fileKey` (default, `vault.key`, 0600) or `memoryKey` key sources. Cross-process file lock, atomic writes, change detection. Metadata listing never returns values. |
| `policy` | `PolicyStore`: allow/ask/deny cells per entity × capability. Rows are agents (`*` = any agent) plus per-session-tree overrides. Resolution order: session → agent → `*` → capability fallback. Optimistic revisions for GUI edits. Exports agent rows only. |
| `bridge` | `PermissionBridge`: makes the table authoritative for `<plugin>.<capability>` actions through the host `permission.evaluate` hook; `check()` calls `permission.assert`, so **ask** shows OpenCode's native prompt. Configured native **deny** rules still win. Fails closed. `guardDirectories` (opt-in) denies native file tools inside private directories. `sessionRoots` maps any session to its tree root. |
| `redact` | `Redactor` + `installRedaction`: masks secrets in tool results (URL/JSON/hex encodings, base64 at any alignment). Scoped to the plugin's own tools by default; `"all"` (native tools too) is opt-in. Never throws. |
| `bundle` | `encryptBundle`/`decryptBundle`: portable export files (scrypt + AES-256-GCM, authenticated header, bounded KDF cost, version migrations). `inspectBundle` reads the header without a passphrase; `diffRecords` builds import previews. |
| `requests` | `SecretRequests`: the agent asks for a secret; the user enters it in the GUI. Stores no secret material. |

All files live in the plugin's data directory (`pluginDataDir`: `$XDG_DATA_HOME/<plugin>`,
default `~/.local/share/<plugin>`), created with mode 0700/0600.

## Security limits

These are best-effort protections against accidents and casual misuse, not a
boundary against code running as the same OS user:

- The key file sits next to the vault. Anything running as you, including the
  agent's shell, can read it. `guardDirectories` is opt-in and blocks only native
  file tools, and only for paths inside the directory.
- Redaction catches known encodings only. A deliberate transformation (reversing,
  splitting, other encodings) gets through.
- "GUI only" for permission edits and export/import is enforced by not exposing
  those operations as agent tools. A same-user process could still call the
  local server directly.

`memoryKey` lets a plugin unlock the vault from a passphrase instead. The vault
file format stays the same.
