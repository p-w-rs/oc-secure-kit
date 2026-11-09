# secure-kit

Shared building blocks for the `oc-*` OpenCode plugins: encrypted file vault,
permission policy store, permission bridge, output redaction and portable
export bundles. Node built-ins only; macOS and Linux.

This is a library, not a plugin. Plugins never depend on this folder directly:
they vendor a packed tarball so each plugin builds from its own folder.

```sh
pixi run --locked test     # typecheck + tests
pixi run --locked pack     # -> .local/pack/oc-secure-kit-<version>.tgz (+ sha256)
```

Then in a plugin: `pixi run vendor-kit ../secure-kit/.local/pack/oc-secure-kit-<version>.tgz`.
