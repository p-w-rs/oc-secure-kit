/** Exact values shorter than this are not redacted: they would mangle ordinary output. Store longer secrets. */
export const MIN_SECRET_LENGTH = 6
/** Encoded fragments (base64 at an offset) must be at least this long to count as a match. */
const MIN_FRAGMENT_LENGTH = 8

export interface Pattern { readonly needle: string; readonly label: string }

/**
 * Best-effort masking of known secret values in text, including common encodings: base64 (standard and URL-safe, at
 * every byte alignment, so substrings of larger base64 blobs are caught), hex, URL encoding and JSON escaping.
 * It cannot catch arbitrary transformations (reversal, other encodings, partial output, encryption).
 */
export function patternsFor(label: string, value: string): Pattern[] {
  if (value.length < MIN_SECRET_LENGTH) return []
  const needles = new Set<string>([value])
  const bytes = Buffer.from(value, "utf8")
  needles.add(encodeURIComponent(value))
  needles.add(JSON.stringify(value).slice(1, -1))
  needles.add(bytes.toString("hex"))
  needles.add(bytes.toString("hex").toUpperCase())
  for (let offset = 0; offset < 3; offset++) {
    const padded = Buffer.concat([Buffer.alloc(offset), bytes])
    const encoded = padded.toString("base64")
    // Characters of the first group depend on the unknown preceding bytes when offset > 0; those of a trailing
    // partial group depend on the following bytes. Keep only the groups fully determined by the secret.
    const start = offset > 0 ? 4 : 0
    const end = Math.floor(padded.length / 3) * 4
    const fragment = encoded.slice(start, end)
    if (fragment.length >= MIN_FRAGMENT_LENGTH) {
      needles.add(fragment)
      needles.add(fragment.replaceAll("+", "-").replaceAll("/", "_"))
    }
  }
  return [...needles].map(needle => ({ needle, label }))
}

export class Redactor {
  #secrets = new Map<string, string>()
  #patterns: Pattern[] = []

  /** Registers or replaces a secret under a label shown in place of it, e.g. `machine:web/sudo`. */
  set(label: string, value: string): void {
    this.#secrets.set(label, value)
    this.#rebuild()
  }
  delete(label: string): void {
    if (this.#secrets.delete(label)) this.#rebuild()
  }
  /** Replaces every registered secret at once. */
  replaceAll(entries: Iterable<readonly [label: string, value: string]>): void {
    this.#secrets = new Map(entries)
    this.#rebuild()
  }
  get size(): number { return this.#secrets.size }

  redact(text: string): string {
    if (!text || !this.#patterns.length) return text
    let result = text
    for (const { needle, label } of this.#patterns) {
      if (result.includes(needle)) result = result.split(needle).join(`[REDACTED:${label}]`)
    }
    return result
  }

  /** Redacts every string inside plain objects and arrays. Other values are returned unchanged. */
  redactDeep<T>(value: T, depth = 0): T {
    if (typeof value === "string") return this.redact(value) as T
    if (depth > 32 || value === null || typeof value !== "object") return value
    if (Array.isArray(value)) return value.map(item => this.redactDeep(item, depth + 1)) as T
    const proto = Object.getPrototypeOf(value)
    if (proto !== Object.prototype && proto !== null) return value
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, this.redactDeep(item, depth + 1)])) as T
  }

  #rebuild(): void {
    // Longest first, so a secret that contains another is masked as a whole.
    this.#patterns = [...this.#secrets].flatMap(([label, value]) => patternsFor(label, value))
      .sort((a, b) => b.needle.length - a.needle.length)
  }
}

interface AfterEvent {
  readonly status: "completed" | "error"
  result?: unknown
  error?: unknown
}
export interface ToolHookHost {
  hook(name: "execute.after", callback: (event: AfterEvent) => Promise<void> | void): Promise<{ dispose(): Promise<void> }>
}

/** Masks registered secrets in every tool's result (including native shell output) before the model sees it. */
export function installRedaction(tool: ToolHookHost, redactor: Redactor): Promise<{ dispose(): Promise<void> }> {
  return tool.hook("execute.after", event => {
    if (!redactor.size) return
    if (event.status === "completed") event.result = redactor.redactDeep(event.result)
    else if (event.error instanceof Error) {
      const masked = redactor.redact(event.error.message)
      if (masked !== event.error.message) {
        try { event.error.message = masked } catch { event.error = Object.assign(new Error(masked), { name: event.error.name }) }
      }
    }
  })
}
