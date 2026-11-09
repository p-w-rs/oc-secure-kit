import { resolve, sep } from "node:path"
import { combineEffects, type Effect, type PolicyStore, type Resolution } from "./policy.js"
import { validName } from "./vault.js"

// Structural subsets of the OpenCode plugin API, so secure-kit does not pin an @opencode/plugin version.
export interface EvaluateEvent {
  readonly sessionID: string
  readonly agent?: string
  readonly action: string
  readonly resources: ReadonlyArray<string>
  readonly metadata?: Record<string, unknown>
  effect: Effect
  message?: string
}
export interface AssertInput {
  sessionID: string
  agent?: string
  action: string
  resources: string[]
  save?: string[]
  metadata?: Record<string, unknown>
  source?: { type: "tool"; messageID: string; id: string }
}
export interface Registration { dispose(): Promise<void> }
export interface PermissionHost {
  assert(input: AssertInput): Promise<void>
  hook(name: "evaluate", callback: (event: EvaluateEvent) => Promise<void> | void): Promise<Registration>
}

/** Returns a session's parent ID, or undefined for a root session. */
export type ParentLookup = (sessionID: string) => Promise<string | undefined>

/** Finds the root of a session tree, so a "this session" override also covers subagents. Results are cached. */
export function sessionRoots(parent: ParentLookup): (sessionID: string) => Promise<string> {
  const cache = new Map<string, string>()
  return async sessionID => {
    const seen: string[] = []
    let current = sessionID
    for (;;) {
      const known = cache.get(current)
      if (known) { current = known; break }
      if (seen.includes(current) || seen.length >= 64) throw new Error("Invalid session ancestry")
      seen.push(current)
      const next = await parent(current)
      if (!next) break
      current = next
    }
    for (const id of seen) cache.set(id, current)
    if (cache.size > 10_000) cache.clear()
    return current
  }
}

export interface CheckInput {
  readonly sessionID: string
  readonly agent?: string
  readonly capability: string
  readonly entities: readonly string[]
  /** Shown in the native approval prompt. Never put secret values here. */
  readonly metadata?: Record<string, unknown>
  readonly source?: { type: "tool"; messageID: string; id: string }
}

/**
 * Makes a plugin's permission table authoritative for its own actions (`<plugin>.<capability>`, resources = entity
 * IDs): an `evaluate` hook sets allow/ask/deny from the table, and `check` asks the host, so **ask** uses OpenCode's
 * native approval prompt. Native configured **deny** rules are evaluated by the host first and still win.
 */
export class PermissionBridge {
  readonly plugin: string
  readonly #policy: PolicyStore
  readonly #root: (sessionID: string) => Promise<string>
  readonly #fallback: (capability: string) => Effect
  #host?: PermissionHost

  constructor(options: {
    plugin: string
    policy: PolicyStore
    root: (sessionID: string) => Promise<string>
    /** Effect when no row sets a cell. Defaults to `ask`. */
    fallback?: (capability: string) => Effect
  }) {
    this.plugin = validName("plugin", options.plugin)
    this.#policy = options.policy
    this.#root = options.root
    this.#fallback = options.fallback ?? (() => "ask")
  }

  action(capability: string): string { return `${this.plugin}.${validName("capability", capability)}` }

  /** The table's decision without prompting (e.g. to decide what to show or inject). */
  async effect(input: { sessionID: string; agent?: string; capability: string; entity: string }): Promise<Resolution> {
    return this.#policy.resolve({
      entity: input.entity, capability: input.capability, agent: input.agent,
      sessionRoot: await this.#root(input.sessionID), fallback: this.#fallback(input.capability),
    })
  }

  /** Resolves when allowed (after prompting for **ask**); rejects when denied or the user declines. */
  async check(input: CheckInput): Promise<void> {
    if (!this.#host) throw new Error(`${this.plugin}: permission bridge is not installed`)
    if (!input.entities.length) throw new Error(`${this.plugin}: permission check needs at least one entity`)
    await this.#host.assert({
      sessionID: input.sessionID,
      ...(input.agent ? { agent: input.agent } : {}),
      action: this.action(input.capability),
      resources: [...input.entities],
      // "Always allow" on the native prompt would be overridden by the table anyway; change the table instead.
      save: [],
      ...(input.metadata ? { metadata: input.metadata } : {}),
      ...(input.source ? { source: input.source } : {}),
    })
  }

  async install(host: PermissionHost): Promise<Registration> {
    this.#host = host
    const prefix = `${this.plugin}.`
    return host.hook("evaluate", async event => {
      if (!event.action.startsWith(prefix)) return
      const capability = event.action.slice(prefix.length)
      try {
        validName("capability", capability)
        const decisions = await Promise.all(event.resources.map(async entity =>
          ({ entity, ...await this.effect({ sessionID: event.sessionID, agent: event.agent, capability, entity }) })))
        event.effect = combineEffects(decisions.map(item => item.effect))
        const denied = decisions.find(item => item.effect === "deny")
        if (denied) event.message = `Denied by the ${this.plugin} permissions table (${capability} on ${denied.entity}). The user can change this in the Review pane.`
      } catch (error) {
        // Fail closed: a broken or unreadable table must never turn into allow.
        event.effect = "deny"
        event.message = `${this.plugin}: permissions unavailable (${(error as Error).message})`
      }
    })
  }
}

/** Native tool actions whose resources are file paths. */
const FILE_ACTIONS = new Set(["read", "edit", "write", "external_directory", "grep", "glob", "list"])

/**
 * Opt-in: denies native file tools inside plugin-private directories (vault, key, policy). This changes native
 * behavior, so plugins enable it only on request. Best-effort: it matches the lexical paths the host reports, so it
 * does not cover shell commands, symlinks, or searches of a parent directory. Never throws.
 */
export async function guardDirectories(host: Pick<PermissionHost, "hook">, plugin: string, directories: readonly string[]): Promise<Registration> {
  const roots = directories.map(dir => resolve(dir))
  const inside = (resource: string) => {
    if (!resource.startsWith("/")) return false
    const path = resolve(resource.endsWith("/*") ? resource.slice(0, -2) : resource)
    return roots.some(root => path === root || path.startsWith(root + sep))
  }
  return host.hook("evaluate", event => {
    try {
      if (!FILE_ACTIONS.has(event.action) || !event.resources.some(inside)) return
      event.effect = "deny"
      event.message = `${plugin} keeps secrets in this directory; native file tools may not access it.`
    } catch {}
  })
}
