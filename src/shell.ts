import type { Redactor } from "./redact.js"
import type { RunDir } from "./rundir.js"

/** Native tools that run shell commands. */
export const SHELL_TOOLS = new Set(["shell", "bash"])
const PENDING_MS = 10 * 60_000
/** How long files of commands still running when the plugin unloads are kept. */
const DISPOSE_GRACE_MS = 30 * 60_000

/** Who runs a command, and where. */
export interface ShellCaller {
  readonly sessionID: string
  readonly agent?: string
  readonly source?: { type: "tool"; messageID: string; id: string }
  /** The command's `workdir` input, if any (absolute, or relative to the session directory). */
  readonly workdir?: string
}

/** What a plugin supplies to one shell command. */
export interface Supply {
  /** Variables added to that shell's environment. */
  readonly env: Record<string, string>
  /** One-line explanations appended to the result for the agent. */
  readonly notes: string[]
  /** Secret values were supplied, so the command's output is masked. */
  readonly secrets: boolean
  readonly runDir?: RunDir
  /** Extra patterns masked in the output (e.g. tokens the command itself prints). Applied when `secrets` is set. */
  readonly mask?: readonly RegExp[]
  /** Runs after the command, before its run dir is removed (e.g. to save updated credentials). Never throws. */
  readonly onDone?: (status: "completed" | "error") => Promise<void> | void
}

interface Pending { readonly callID: string; readonly supply: Supply; readonly at: number }
interface BeforeEvent { readonly tool: string; readonly sessionID: string; readonly agent: string; readonly messageID: string; readonly id: string; input: unknown }
interface CreateEvent { readonly command: string; env: Record<string, string | undefined> }
interface AfterEvent { readonly tool: string; readonly id: string; readonly input: unknown; readonly status: "completed" | "error"; result?: unknown; error?: unknown }

const field = (input: unknown, name: string) =>
  input && typeof input === "object" && typeof (input as Record<string, unknown>)[name] === "string" ? (input as Record<string, string>)[name] : undefined

/** Appends a note to a native shell result without changing its structure. */
export function appendNote(result: unknown, note: string, plugin: string): unknown {
  if (!result || typeof result !== "object") return result
  const copy = { ...(result as Record<string, unknown>) }
  const line = `[${plugin}] ${note}`
  const join = (text: string) => `${text}${text === "" || text.endsWith("\n") ? "" : "\n"}${line}`
  if (typeof copy.content === "string") copy.content = join(copy.content)
  else if (Array.isArray(copy.content)) {
    const content = [...copy.content]
    const last = content.findLastIndex(part => part && typeof part === "object" && (part as { type?: unknown }).type === "text")
    if (last >= 0) content[last] = { ...content[last], text: join((content[last] as { text: string }).text) }
    else content.push({ type: "text", text: line })
    copy.content = content
  }
  if (copy.output && typeof copy.output === "object" && typeof (copy.output as { output?: unknown }).output === "string") {
    copy.output = { ...(copy.output as object), output: join((copy.output as { output: string }).output) }
  }
  return copy
}

const maskText = (text: string, patterns?: readonly RegExp[]) => {
  if (!patterns?.length || !text) return text
  let result = text
  for (const pattern of patterns) result = result.replace(new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`), "[REDACTED:token]")
  return result
}
function maskDeep<T>(value: T, patterns: readonly RegExp[] | undefined, depth = 0): T {
  if (!patterns?.length) return value
  if (typeof value === "string") return maskText(value, patterns) as T
  if (depth > 32 || value === null || typeof value !== "object") return value
  if (Array.isArray(value)) return value.map(item => maskDeep(item, patterns, depth + 1)) as T
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, inner]) => [key, maskDeep(inner, patterns, depth + 1)])) as T
}

export const exitCode = (result: unknown): number | undefined => {
  const output = result && typeof result === "object" ? (result as { output?: unknown }).output : undefined
  const exit = output && typeof output === "object" ? (output as { exit?: unknown }).exit : undefined
  return typeof exit === "number" ? exit : undefined
}

export interface ShellSupplierOptions {
  readonly plugin: string
  /** Decides what to supply; undefined leaves the command exactly as in plain OpenCode. May prompt (permission ask). */
  readonly prepare: (command: string, caller: ShellCaller) => Promise<Supply | undefined>
  readonly redactor: Redactor
  readonly warn: (message: string, error?: unknown) => void
  /** Optional note for commands the plugin did not supply to (e.g. a usage tip after a failure). Must be fast. */
  readonly annotate?: (command: string, result: unknown) => string | undefined
}

/**
 * Supplies values to native shell commands. `before` (tool hook: knows session and agent; the host awaits it)
 * prepares; `create` (shell hook, same command string, ~1 ms later) adds the env to that one shell; `after` masks
 * secrets and appends notes. Each step is a no-op for commands the plugin does not handle, and none blocks a command.
 */
export class ShellSupplier {
  #pending = new Map<string, Pending[]>()
  #byCall = new Map<string, Pending>()
  constructor(private readonly options: ShellSupplierOptions) {}

  async before(event: BeforeEvent): Promise<void> {
    if (!SHELL_TOOLS.has(event.tool)) return
    const command = field(event.input, "command")
    if (!command) return
    let supply: Supply | undefined
    try {
      const workdir = field(event.input, "workdir")
      supply = await this.options.prepare(command, {
        sessionID: event.sessionID, agent: event.agent, source: { type: "tool", messageID: event.messageID, id: event.id },
        ...(workdir && { workdir }),
      })
    } catch (error) {
      this.options.warn("could not prepare shell values", error)
      return
    }
    if (!supply) return
    this.#expire()
    const pending: Pending = { callID: event.id, supply, at: Date.now() }
    this.#pending.set(command, [...this.#pending.get(command) ?? [], pending])
    this.#byCall.set(event.id, pending)
  }

  create(event: CreateEvent): void {
    try {
      const queue = this.#pending.get(event.command)
      const pending = queue?.shift()
      if (!queue?.length) this.#pending.delete(event.command)
      if (pending) Object.assign(event.env, pending.supply.env)
    } catch (error) { this.options.warn("could not add shell values", error) }
  }

  /** Masks and annotates the result synchronously, then runs the supply's onDone (awaited) and cleans up. */
  after(event: AfterEvent): Promise<void> | void {
    if (!SHELL_TOOLS.has(event.tool)) return
    let finish: Pending | undefined
    try {
      const pending = this.#byCall.get(event.id)
      this.#byCall.delete(event.id)
      const command = field(event.input, "command")
      if (pending) {
        if (command) {
          const queue = this.#pending.get(command)?.filter(item => item !== pending)
          if (queue?.length) this.#pending.set(command, queue); else this.#pending.delete(command)
        }
        finish = pending
      }
      if (event.status !== "completed") {
        if (pending?.supply.secrets && event.error instanceof Error) {
          try { event.error.message = maskText(this.options.redactor.redact(event.error.message), pending.supply.mask) } catch {}
        }
      } else {
      let result = event.result
      if (pending?.supply.secrets) result = maskDeep(this.options.redactor.redactDeep(result), pending.supply.mask)
      for (const note of pending?.supply.notes ?? []) result = appendNote(result, note, this.options.plugin)
      if (!pending && command && this.options.annotate) {
        const note = this.options.annotate(command, result)
        if (note) result = appendNote(result, note, this.options.plugin)
      }
      event.result = result
      }
    } catch (error) { this.options.warn("could not finish shell values", error) }
    if (!finish) return
    const done = finish
    const cleanup = () => { done.supply.runDir?.removeLater() }
    if (!done.supply.onDone) { cleanup(); return }
    return (async () => {
      try { await done.supply.onDone!(event.status) } catch (error) { this.options.warn("could not save after the command", error) }
      cleanup()
    })()
  }

  #expire(): void {
    const cutoff = Date.now() - PENDING_MS
    for (const [command, queue] of this.#pending) {
      const fresh = queue.filter(item => {
        if (item.at >= cutoff) return true
        this.#byCall.delete(item.callID)
        void item.supply.runDir?.remove().catch(() => {})
        return false
      })
      if (fresh.length) this.#pending.set(command, fresh); else this.#pending.delete(command)
    }
  }

  /**
   * Called when the plugin unloads (e.g. a config change reloads plugins). Commands that already started keep running
   * and may still need their files (keys, askpass helpers), so those are removed later, not now.
   */
  dispose(): void {
    for (const pending of this.#byCall.values()) pending.supply.runDir?.removeLater(DISPOSE_GRACE_MS)
    this.#pending.clear()
    this.#byCall.clear()
  }
}
