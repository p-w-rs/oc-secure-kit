# OpenCode integration plugins: plan

Status: all plugins below are built and released as 1.0.0 except SAP ByD (dropped). This document records the
original plan and design decisions; each plugin's README describes what was built.

Target: OpenCode V2 2.2.6+ on macOS and Linux, with Pixi as the only project tool.
No platform-specific services (no Keychain, libsecret, etc.). Runtime needs are
Node built-ins (`node:crypto`, `node:fs`) and standard OpenSSH / sudo binaries.
Every plugin's state can be exported and imported into another OpenCode install
running the same plugin.

## Design principles (apply to every plugin)

1. **Usability and agent capability come first, security second.** The baseline is
   agents reading raw env vars, so any structure is an improvement. Prefer
   working defaults over prompts.
2. **Never change how vanilla OpenCode works.** The plugins only *add* tools, a
   Review tab, settings and env vars. They must not:
   - deny, prompt for or slow down native tools (read, edit, shell, grep, ...),
   - rewrite native tool input or output by default,
   - add global locks, barriers or gates (the `open-enhance` checkpoint lesson),
   - change the meaning of existing env vars or native permission rules.
3. **Fail open for native work, fail closed only for the plugin's own actions.**
   If a plugin hook errors, it does nothing and logs. If setup fails, the plugin
   disables its own features; OpenCode keeps working. The permission table can
   deny only `<plugin>.*` actions.
4. **Hooks are fast and never throw.** Anything that runs on every tool call or
   every shell must be O(small) and catch its own errors.
5. **Opt-in for anything intrusive.** Global output redaction and the native
   file-tool guard on the plugin's data directory are off by default.

## Plugins and layout

| Folder | Purpose | Sign-in (as built) |
|---|---|---|
| `oc-secure-kit/` | Shared library, packed and vendored into each plugin | — |
| `oc-machine/` | Machines: SSH config, sudo, env vars, permission table | SSH key / agent / password / generated key |
| `oc-github/` | Multiple GitHub accounts with per-account permissions | Browser (device flow) OAuth + SSO, token; SSH keys |
| `oc-atlassian/` | Jira + Confluence | Browser OAuth via Rovo MCP (DCR + PKCE); Cloud API token; DC PAT |
| `oc-runpod/` | Pods, serverless, storage; SSH/rsync into pods | Browser sign-in (MCP) issuing an API key; API key |
| `oc-rhythms/` | Rhythms (rhythms.ai) OKRs, check-ins, documents | Browser OAuth via Rhythms MCP (DCR + PKCE) |
| `oc-azure/` | Azure via the agent's own `az`; SSH into VMs | Azure CLI sign-in (browser, device code, service principal) |
| `oc-m365/` | Outlook, Teams, OneDrive, SharePoint via Microsoft Graph | Entra ID auth code + PKCE / device code (admin consent may be required) |
| ~~`oc-sapbyd/`~~ | Dropped: ByDesign APIs need a communication user or admin-registered OAuth client; SSO sessions are not accepted | — |

Each plugin is installed, configured, stored and versioned on its own. Plugins
never read each other's storage. When two are installed together, they cooperate
through a declared RPC/GUI contract (for example, GitHub adds columns to the
machine table). Without the partner plugin, each works on its own.

## Project layout: self-contained Pixi projects

Each folder is its own independent Pixi project and git repo, following the
`open-claude` pattern (the Node-only, cross-platform one). Nothing depends on a
parent workspace, a global Node/npm, or a system OpenCode.

```text
opencode-plugins/
  secure-kit/      pixi.toml  package.json  npm-shrinkwrap.json  src/ test/ scripts/
  oc-machine/      pixi.toml  package.json  npm-shrinkwrap.json  plugin/ test/ scripts/ vendor/ docs/
  oc-github/       ...same shape
  ...
```

Every project's `pixi.toml`:

```toml
[workspace]
name = "oc-machine"
channels = ["conda-forge"]
platforms = ["osx-arm64", "osx-64", "linux-64", "linux-aarch64"]

[dependencies]
nodejs = "24.*"
openssh = "*"   # pinned ssh/ssh-keygen/ssh-copy-id for tests (runtime uses the system or this one)

[tasks]
deps     = "npm ci --ignore-scripts --cache .local/npm-cache"
check    = { cmd = "npm run check", depends-on = ["deps"] }
test     = { cmd = "npm test", depends-on = ["check"] }
build    = { cmd = "npm run build", depends-on = ["deps"] }   # server plugin + GUI bundle (vite)
install  = { cmd = "node scripts/install.mjs", depends-on = ["build"] }
rollback = { cmd = "node scripts/install.mjs --rollback", depends-on = ["deps"] }
uninstall = { cmd = "node scripts/install.mjs --uninstall", depends-on = ["deps"] }
doctor   = { cmd = "node scripts/doctor.mjs", depends-on = ["build"] }
pack     = { cmd = "node scripts/pack.mjs", depends-on = ["build"] }
```

- Users run `pixi run --locked install` (snapshot install + a backed-up,
  comment-preserving edit of the global OpenCode config, same as the existing
  plugins, with `--rollback` / `--uninstall`).
- Locked: `pixi.lock` + `npm-shrinkwrap.json`. Pinned `@opencode/plugin` 2.2.6,
  plus a repo-local `@opencode/cli` for host smoke tests. Scratch and test data
  go in `.local/` (gitignored).
- **How `secure-kit` is shared:** `secure-kit` is its own Pixi project.
  `pixi run --locked pack` produces `secure-kit-<version>.tgz`. Each plugin
  commits that tarball under `vendor/` and depends on it as `file:vendor/...`
  (the same mechanism `open-enhance` uses for `gitlab-ai-provider`). Each plugin
  is therefore buildable from its own folder alone, and upgrades are an
  explicit vendored-version bump per plugin.
- No Python is needed unless a later plugin requires it. If one does, it gets
  added to that project's own `pixi.toml` only.

## `secure-kit` (shared library)

1. **Vault**: one encrypted file per plugin, `<data>/<plugin>/vault.json`.
   Each secret is encrypted with AES-256-GCM and its entity/name is bound as
   associated data, so swapping or relabelling entries makes decryption fail.
   The key is 32 random bytes stored in `<data>/<plugin>/vault.key` (mode
   0600), created on first use. Plugin config holds only secret references.
   Secrets are never put in argv; they reach helpers through stdin or pipes.
   Writes are atomic (temp file + rename).
2. **Secret slots**: the agent can *request* a secret (name + purpose). The
   request shows up in the GUI and the user types the value. Agent tools can only
   report whether a slot is `set` or `unset`.
3. **Policy store**: an allow/ask/deny table per entity, edited only from the
   GUI over RPC. No agent tool can change it. An optional guard (off by default)
   denies native file tools on the plugin data directory.
4. **Permission bridge**: plugin actions (`oc-machine.sudo`, `oc-github.push`, ...)
   go through `ctx.permission.assert`, and the policy table sets allow/ask/deny.
   **Ask** uses OpenCode's native approval prompt. Only `<plugin>.*` actions are
   affected; native actions are never touched.
5. **Redactor**: by default it masks secret values in the plugin's **own** tool
   output only. Masking every tool's output is opt-in (`redactAllTools: true`),
   because it changes native results: for example, a redacted `.env` read would
   make a later edit write the placeholder back into the file.
6. **GUI**: a shared permission-table component (Solid), a secret-entry
   dialog, and Export/Import buttons.
7. **Portable bundles**: each plugin uses one bundle format.
   - File: `<plugin>-<date>.ocbundle`, a JSON envelope
     `{ format, plugin, schemaVersion, kdf: scrypt params + salt, nonce, ciphertext }`.
   - The plaintext holds config, permission tables (agent rows only; session
     overrides are dropped) and secret values.
   - Everything is encrypted with a key derived (scrypt) from an export
     passphrase entered in the GUI. Bundles never contain the local
     `vault.key`. Importing re-encrypts the secrets under the destination's key.
   - Import shows a preview (entities added, changed or conflicting, and any
     permission changes) with merge or replace per entity. Nothing is written
     until you confirm.
   - Schema migrations run on import, so older bundles still load.
   - Export and import are **GUI only**. The agent has no tool for either.
   - Machine-specific values: `isLocal` is not exported (on import you choose
     which machine is "this machine"). Key-file paths are exported as given;
     generated keys are stored in the vault, so they move with the bundle.

### Security limits (your chosen settings)

- Permission changes need only a GUI click, and env vars are always injected
  into the agent's shell. The agent runs commands as your OS user, so a
  determined agent could leak an injected value (for example, an encoding the
  redactor misses) or call the local RPC endpoint. Protection is **best-effort
  against accidents and casual misuse. It is not a hard security boundary.**
- **Key file on disk:** the vault key sits next to the vault with 0600
  permissions. That stops other users and casual reads, but the agent's shell
  runs as you, so it *could* read the key and decrypt the vault. The optional
  directory guard blocks only native file tools, never shell. The encryption
  mainly protects against copying the folder elsewhere, backups, and accidental
  reads. Export bundles are protected separately by their own passphrase.
- **Stronger by design:** sudo passwords, SSH key passphrases and SSH login
  passwords never enter the agent's shell. Plugin tools use them internally.
- **Upgrade path, available later without redesign:** an optional master
  passphrase (unlock in the GUI, key kept only in memory) can replace the key
  file. The vault format already supports either key source.

## `oc-machine` (build first)

### Model: plugins broadcast, the agent uses its own shell

The plugin never runs work for the agent. It (1) tells the agent what exists, and
(2) supplies values to the agent's **own native shell commands** when a command
asks for them, after a permission check. With nothing referenced, a shell
command runs exactly as in plain OpenCode.

1. **Inventory**: the `machine_list` tool description carries a short summary of
   machines and env vars (names + descriptions, never values), refreshed when
   the configuration changes.
2. **Use**: the agent writes `$HF_TOKEN` or `ssh -F "$OCM_SSH_CONFIG" gpu-2` in
   its normal shell command. A `tool.execute.before` hook on the native `shell`
   tool (it carries session, agent and the exact command, and the host waits for
   it) checks the table: **allow** proceeds, **ask** shows the native pop-up,
   **deny** skips. The matching `shell.create.before` (same command string, ~1 ms
   later; verified on 2.2.6) then adds the granted values to that one shell only.
3. **Never blocks**: a denied or declined value is simply not supplied; the
   command still runs, and a one-line note in its result says why.
4. **Masking**: secret values are masked in the output of the plugin's own tools
   and of shell calls the plugin supplied secrets to. Nothing else is touched.

### Data model (non-secret, editable by the agent)

```text
machine:
  id, label, os (macos|linux), notes
  local (this computer; per-install, not exported)
  ssh: host, user, port, proxyJump, auth (agent|key|password|generated),
       identityFile, identityAgent, forwardX11, forwardX11Trusted, forwardAgent,
       localForwards[], remoteForwards[], serverAliveInterval, options{}
  publicKey (generated keys)
  secrets (vault): sudo, ssh-password, key-passphrase, ssh-key (generated)
env var (global, usable on any machine):
  name, description, secret, value (non-secret only)
  secret value in the vault
```

### Permission table (Review pane side tab + Settings page)

- **Machines table**: one per machine, columns `ssh`, `sudo`, `x11`,
  `agent-forward`, `manage`, `remove`, plus columns from other plugins.
- **Env vars table**: one column per variable (`use`, `manage`, `remove`).
- Rows: one per agent, an any-agent (`*`) row, and a **This session** override
  covering the session tree. Cells are **Allow / Ask / Deny**.
- Unset cells default to **allow**, except `sudo` and `remove` (**ask**).
- Everything is checked per call with the calling agent and session, so the full
  table applies to the native shell too.

### Agent tools (setup only; work happens in the native shell)

| Tool | What it does |
|---|---|
| `machine_list` / `machine_get` | Machines, env vars, which secrets are set, this agent's permissions |
| `machine_upsert` / `machine_remove` | Machine config (removal asks) |
| `machine_env_set` / `machine_env_remove` | Global env vars with descriptions |
| `machine_request_secret` | Ask the user for a machine secret or a secret env value |
| `machine_ssh_keygen` | Generate an ed25519 key into the vault, optionally install it with the machine's current login |
| `machine_test` | Connect and report auth, OS and reachability |
| `machine_ssh_config` | Show the generated config (debugging) |

### Shell references the plugin understands

| In the command | Supplied for that command |
|---|---|
| `$NAME` / `${NAME}` of a defined env var | its value (`use` on that var) |
| `$OCM_SSH_CONFIG` + machine IDs (and their jump hosts) | a per-command ssh config with keys and forwarding as allowed, plus an `SSH_ASKPASS` helper for password/passphrase logins (`ssh`, `x11`, `agent-forward`) |
| `$OCM_SUDO_PASSWORD` | sudo password of the one targeted machine (the ssh target, else this computer) (`sudo`) |
| `sudo -A` | `SUDO_ASKPASS` helper for this computer (`sudo`) |

Per-command files (config, materialized keys, askpass answers) go in a private
run directory that is deleted shortly after the command finishes.
Remote use of a variable: `ssh -F "$OCM_SSH_CONFIG" gpu-2 "HF_TOKEN=$HF_TOKEN python x.py"`.

### Milestones

0. Scaffold the `secure-kit` and `oc-machine` Pixi projects (pixi.toml, locks, tsconfig,
   vite GUI config, install/doctor/pack scripts, `.gitignore`), and confirm
   `pixi run --locked test` passes on an empty plugin.
1. `secure-kit`: file vault + key file, policy store, permission bridge, redactor,
   bundle export/import with migrations, plus tests (round-trip, tamper, wrong passphrase).
2. Machine config CRUD tools, `ssh_config` generator (tested with `ssh -G`).
3. Native-shell integration: per-command env vars and ssh config, askpass for
   ssh passwords/passphrases and sudo, generated keys, `machine_test`, inventory in tool descriptions.
4. GUI: Review-pane tab with the table, secret-entry dialog, Export/Import, Settings page.
5. Install script (Pixi) in the style of `open-enhance`, docs, live Desktop testing
   on macOS, plus CLI/server tests on Linux, including exporting on one host and importing on the other.

## How GitHub fits with machines (built second)

- GitHub accounts are global identities: `work` (HTTPS + OAuth with SAML SSO
  through Microsoft), `personal-ssh`, `bot-token`, ...
- Git is routed per account **without editing global git config**: injected
  `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n` env vars point
  `credential.https://github.com/<org>.helper` at the plugin's helper, and
  `GIT_SSH_COMMAND` selects the key for SSH accounts.
- Per-account permissions (read, push, push to default branch, force push,
  PR, issues, admin) are a table in the same Review tab. On a machine, each
  account is also a column in that machine's table.
- Open question for later: the git credential protocol can't tell a read from
  a push, so blocking push for HTTPS needs either a read-only credential or the
  plugin's GitHub tools. We'll settle this when building the GitHub plugin.

## Questions for later plugins

- GitHub: is it github.com with an SSO-enforced org, or GitHub Enterprise
  Managed Users / ghe.com? Is Git Credential Manager or `gh` approved by your org?
- Atlassian: Cloud or Data Center? Is Atlassian's official remote MCP server
  acceptable?
- RunPod: should pods automatically become machines?
- Rhythms: API access and authentication method.
- SAP ByD: tenant URL style; is a communication arrangement available?

## `oc-github` (second plugin) — design

### General, not tied to one person's setup
Any number of accounts. Each account is configured on its own:
- **Host:** github.com or a GitHub Enterprise Server host.
- **Git transport:** SSH (plugin-generated key, or an existing key file) or HTTPS
  (with the account's token), or none (API only).
- **API/HTTPS login:** browser sign-in (device flow through an OAuth app: GitHub
  CLI's by default, client ID configurable), a token the user pastes, or none.
- **Commit identity:** name and email (defaults from the GitHub profile, using
  the private noreply address).
- **Per-owner transport overrides:** e.g. "use SSH for `p-w-rs/*`, HTTPS
  elsewhere", replacing the kind of URL rewrite people put in their own git config.
- **System git settings:** ignored by default (the plugin uses only its own
  per-account settings file); an option per account layers the user's own git
  config underneath instead.

What exists on the author's Mac today (no `gh`, no GCM, a personal SSH rewrite)
is only a test case, not an assumption.

### Never blocks the system git
The plugin only supplies values to `git`/`gh` commands it matched to one of its
accounts. Everything else (repos whose owner matches no account, commands
prefixed `OCG_ACCOUNT=none`, any non-git command) runs exactly as plain
OpenCode, with the user's own git, keys and `gh` login. If the user asks the
agent to use their system git, the agent does so with `OCG_ACCOUNT=none`.
Auto-picking can be turned off globally; then only explicit `OCG_ACCOUNT=<name>`
commands get plugin credentials.

### Accounts vs orgs (made explicit to the agent)
- **Account** = an identity the plugin signs in as (name chosen by the user).
- **Org** = an organization an account can reach, with SSO status, discovered
  from the API and refreshed periodically.
- Inventory example:
  `Accounts: work (jdoe_x, https) → orgs: acme-corp [SSO ok]; personal (p-w-rs, ssh) → orgs: none`.

### Choosing the account
Explicit `OCG_ACCOUNT=<name>` wins. Otherwise: repo remote owner, or `gh -R owner/repo`
/ `owner/repo` arguments, matched to accounts (the account itself, or an org it
reaches). Zero or several matches: nothing supplied, and the note tells the agent
to use context (conversation, previous commands) or ask the user, then rerun with
`OCG_ACCOUNT=...`.

### Per command
- `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=<account settings file>` (unless
  the account layers the system config), credential helper fed from the vault,
  `GIT_SSH_COMMAND` with the account's key, `GH_TOKEN` and `GH_HOST` for `gh`.
- A bundled pinned `gh` is put first on PATH only for `gh` commands, and only
  when the system has none.
- On oc-machine hosts: SSH agent forwarding of the account key, or
  `$OCG_TOKEN_<account>` passed explicitly, under the `remote` capability.

### Sign-in for SSO orgs
Device flow: the GUI shows the code and opens the device page; Microsoft (or
any IdP) SSO happens in the browser. If GitHub reports the token needs SSO
authorization for an org (`X-GitHub-SSO`), the GUI shows **Authorize for <org>**.
Tokens are kept in the vault and refreshed when the app issues refresh tokens.
Fallbacks if an org blocks the default app: another approved OAuth app's client
ID, a pasted token, or a GitHub App the org approves.

### Permissions (Review pane and Settings, like oc-machine)
Entity = account, with optional per-org override rows (`account/org`).
Capabilities: read, push, push-default-branch, force-push, delete-branch, pr,
pr-merge, review, issues, releases, actions, repo-create, repo-delete,
repo-settings, secrets, org-admin, gists, packages, api-other, remote.
- Every cell is editable in the GUI; **Allow always** on a prompt writes allow.
- Shipped defaults are only a starting point: allow everything, except ask for
  force-push, repo-delete, repo-settings, secrets, org-admin and api-other. The
  defaults themselves are editable (the "Any agent" row).
- The GUI also shows what GitHub itself allows the account (role per org/repo,
  branch protection) so users can mirror it; GitHub still enforces its own rules.
- Classified from the command text (`git push --force`, `gh pr merge`,
  `gh repo delete`, `gh api -X DELETE ...`); unknown writes count as api-other.
