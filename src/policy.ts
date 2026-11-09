import { stat } from "node:fs/promises"
import { join } from "node:path"
import { atomicWrite, ensurePrivateDir, readJson, Serial, withFileLock } from "./fsutil.js"
import { validName } from "./vault.js"

export const POLICY_FORMAT = "oc-policy/1"
export type Effect = "allow" | "ask" | "deny"
export const EFFECTS: readonly Effect[] = ["allow", "ask", "deny"]

/** `*` is the "any agent" row; other keys are agent IDs. Each row maps capability -> effect. */
export type AgentRows = Record<string, Record<string, Effect>>
export interface EntityPolicy { agents: AgentRows }
export interface SessionOverride { updatedAt: string; entities: Record<string, Record<string, Effect>> }
export interface PolicyDoc {
  format: typeof POLICY_FORMAT
  revision: number
  entities: Record<string, EntityPolicy>
  /** Keyed by root session ID; applies to that session tree. Never exported. */
  sessions: Record<string, SessionOverride>
}

export type Row = { readonly agent: string } | { readonly session: string }
export interface CellChange {
  readonly entity: string
  readonly row: Row
  readonly capability: string
  /** `null` clears the cell so the next level of the resolution order applies. */
  readonly effect: Effect | null
}
export interface Resolution {
  readonly effect: Effect
  /** Which level decided: the session override, the agent's row, the `*` row, or the capability default. */
  readonly source: "session" | "agent" | "any-agent" | "default"
}
export interface ResolveInput {
  readonly entity: string
  readonly capability: string
  readonly agent?: string
  readonly sessionRoot?: string
  /** Used when no row sets the cell. Defaults to `ask`. */
  readonly fallback?: Effect
}

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000
const AGENT = /^(\*|[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127})$/
const SESSION = /^[A-Za-z0-9_-]{1,200}$/

export class StaleRevisionError extends Error {
  constructor(readonly current: number) { super(`Permissions changed (now revision ${current}); reload and try again`) }
}

const empty = (): PolicyDoc => ({ format: POLICY_FORMAT, revision: 0, entities: {}, sessions: {} })

/** Pure resolution: session override, then the agent's row, then the `*` row, then the fallback. */
export function resolveEffect(doc: PolicyDoc, input: ResolveInput): Resolution {
  const session = input.sessionRoot ? doc.sessions[input.sessionRoot]?.entities[input.entity]?.[input.capability] : undefined
  if (session) return { effect: session, source: "session" }
  const rows = doc.entities[input.entity]?.agents
  const agent = input.agent && input.agent !== "*" ? rows?.[input.agent]?.[input.capability] : undefined
  if (agent) return { effect: agent, source: "agent" }
  const any = rows?.["*"]?.[input.capability]
  if (any) return { effect: any, source: "any-agent" }
  return { effect: input.fallback ?? "ask", source: "default" }
}

/** Strictest of several effects: any deny wins, then any ask. */
export function combineEffects(effects: Iterable<Effect>): Effect {
  let result: Effect = "allow"
  for (const effect of effects) {
    if (effect === "deny") return "deny"
    if (effect === "ask") result = "ask"
  }
  return result
}

/**
 * Durable permission table. This class does not decide *who* may edit it; plugins expose mutations only over
 * GUI RPC, never as agent tools.
 */
export class PolicyStore {
  readonly path: string
  #doc: PolicyDoc = empty()
  #stamp = ""
  #serial = new Serial()
  #listeners = new Set<(doc: PolicyDoc) => void>()

  private constructor(path: string) { this.path = path }

  static async open(dir: string): Promise<PolicyStore> {
    await ensurePrivateDir(dir)
    const store = new PolicyStore(join(dir, "policy.json"))
    await store.reload()
    return store
  }

  /** Re-reads the file when it changed on disk (e.g. edited by another OpenCode server sharing this directory). */
  async reload(): Promise<PolicyDoc> {
    let stamp = "missing"
    try { const info = await stat(this.path); stamp = `${info.mtimeMs}:${info.size}:${info.ino}` }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error }
    if (stamp !== this.#stamp) {
      this.#doc = validateDoc(await readJson<PolicyDoc>(this.path) ?? empty(), this.path)
      this.#stamp = stamp
    }
    return this.snapshot()
  }

  /** A deep copy of the last loaded table; safe to send to the GUI. */
  snapshot(): PolicyDoc { return structuredClone(this.#doc) }

  async resolve(input: ResolveInput): Promise<Resolution> {
    await this.reload()
    return resolveEffect(this.#doc, input)
  }

  /** Applies cell edits atomically. With `expectedRevision`, fails if someone else changed the table first. */
  async setCells(changes: readonly CellChange[], expectedRevision?: number): Promise<PolicyDoc> {
    for (const change of changes) checkChange(change)
    return this.#mutate(doc => {
      if (expectedRevision !== undefined && doc.revision !== expectedRevision) throw new StaleRevisionError(doc.revision)
      const now = new Date().toISOString()
      for (const change of changes) {
        let row: Record<string, Effect>
        if ("agent" in change.row) {
          const entity = doc.entities[change.entity] ??= { agents: {} }
          row = entity.agents[change.row.agent] ??= {}
        } else {
          const session = doc.sessions[change.row.session] ??= { updatedAt: now, entities: {} }
          session.updatedAt = now
          row = session.entities[change.entity] ??= {}
        }
        if (change.effect === null) delete row[change.capability]
        else row[change.capability] = change.effect
      }
      prune(doc)
    })
  }

  /** Copies one entity's agent rows to another (e.g. a duplicated machine). */
  async copyEntity(from: string, to: string): Promise<PolicyDoc> {
    validName("entity", to)
    return this.#mutate(doc => {
      const source = doc.entities[from]
      if (source) doc.entities[to] = structuredClone(source)
    })
  }

  async renameEntity(from: string, to: string): Promise<PolicyDoc> {
    validName("entity", to)
    return this.#mutate(doc => {
      if (from === to) return
      if (doc.entities[to]) throw new Error(`Permissions for ${to} already exist`)
      const entity = doc.entities[from]
      if (entity) { doc.entities[to] = entity; delete doc.entities[from] }
      for (const session of Object.values(doc.sessions)) {
        const cells = session.entities[from]
        if (cells) { session.entities[to] = cells; delete session.entities[from] }
      }
    })
  }

  removeEntity(entity: string): Promise<PolicyDoc> {
    return this.#mutate(doc => {
      delete doc.entities[entity]
      for (const session of Object.values(doc.sessions)) delete session.entities[entity]
      prune(doc)
    })
  }

  /** Removes a capability column everywhere (e.g. a deleted env var). */
  removeCapability(entity: string, capability: string): Promise<PolicyDoc> {
    return this.#mutate(doc => {
      for (const row of Object.values(doc.entities[entity]?.agents ?? {})) delete row[capability]
      for (const session of Object.values(doc.sessions)) delete session.entities[entity]?.[capability]
      prune(doc)
    })
  }

  clearSession(sessionRoot: string): Promise<PolicyDoc> {
    return this.#mutate(doc => { delete doc.sessions[sessionRoot] })
  }

  /** Agent rows for export. Session overrides are local and never exported. */
  async exportEntities(entities?: readonly string[]): Promise<Record<string, EntityPolicy>> {
    await this.reload()
    const wanted = entities ? new Set(entities) : undefined
    return structuredClone(Object.fromEntries(Object.entries(this.#doc.entities).filter(([id]) => !wanted || wanted.has(id))))
  }

  /** Replaces the agent rows of each listed entity with the imported ones. */
  async importEntities(incoming: Record<string, EntityPolicy>): Promise<PolicyDoc> {
    const checked = validateEntities(incoming, "import")
    return this.#mutate(doc => { for (const [id, policy] of Object.entries(checked)) doc.entities[id] = policy })
  }

  onChange(listener: (doc: PolicyDoc) => void): () => void {
    this.#listeners.add(listener)
    return () => { this.#listeners.delete(listener) }
  }

  #mutate(change: (doc: PolicyDoc) => void): Promise<PolicyDoc> {
    return this.#serial.run(() => withFileLock(this.path, async () => {
      const doc = validateDoc(await readJson<PolicyDoc>(this.path) ?? empty(), this.path)
      change(doc)
      doc.revision += 1
      await atomicWrite(this.path, JSON.stringify(doc, null, 2) + "\n")
      this.#doc = doc
      this.#stamp = ""
      const snapshot = this.snapshot()
      for (const listener of this.#listeners) { try { listener(snapshot) } catch {} }
      return snapshot
    }))
  }
}

function checkChange(change: CellChange): void {
  validName("entity", change.entity)
  validName("capability", change.capability)
  if (change.effect !== null && !EFFECTS.includes(change.effect)) throw new Error(`Invalid effect ${JSON.stringify(change.effect)}`)
  if ("agent" in change.row) { if (!AGENT.test(change.row.agent)) throw new Error(`Invalid agent ${JSON.stringify(change.row.agent)}`) }
  else if (!SESSION.test(change.row.session)) throw new Error("Invalid session ID")
}

function prune(doc: PolicyDoc): void {
  const cutoff = Date.now() - SESSION_TTL_MS
  for (const [id, session] of Object.entries(doc.sessions)) {
    for (const [entity, cells] of Object.entries(session.entities)) if (!Object.keys(cells).length) delete session.entities[entity]
    if (!Object.keys(session.entities).length || Date.parse(session.updatedAt) < cutoff) delete doc.sessions[id]
  }
  for (const [id, entity] of Object.entries(doc.entities)) {
    for (const [agent, row] of Object.entries(entity.agents)) if (!Object.keys(row).length) delete entity.agents[agent]
    if (!Object.keys(entity.agents).length) delete doc.entities[id]
  }
}

function validateCells(value: unknown, where: string): Record<string, Effect> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`Invalid permission row in ${where}`)
  for (const [capability, effect] of Object.entries(value)) {
    validName("capability", capability)
    if (!EFFECTS.includes(effect as Effect)) throw new Error(`Invalid effect for ${capability} in ${where}`)
  }
  return value as Record<string, Effect>
}

function validateEntities(value: unknown, where: string): Record<string, EntityPolicy> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`Invalid permissions in ${where}`)
  for (const [id, entity] of Object.entries(value as Record<string, EntityPolicy>)) {
    validName("entity", id)
    if (!entity || typeof entity.agents !== "object" || !entity.agents) throw new Error(`Invalid permissions for ${id} in ${where}`)
    for (const [agent, row] of Object.entries(entity.agents)) {
      if (!AGENT.test(agent)) throw new Error(`Invalid agent ${JSON.stringify(agent)} in ${where}`)
      validateCells(row, where)
    }
  }
  return value as Record<string, EntityPolicy>
}

function validateDoc(doc: PolicyDoc, where: string): PolicyDoc {
  if (doc.format !== POLICY_FORMAT || !Number.isSafeInteger(doc.revision)) throw new Error(`Unsupported permissions file: ${where}`)
  validateEntities(doc.entities, where)
  if (!doc.sessions || typeof doc.sessions !== "object") throw new Error(`Corrupt permissions file: ${where}`)
  for (const session of Object.values(doc.sessions)) for (const cells of Object.values(session.entities ?? {})) validateCells(cells, where)
  return doc
}
