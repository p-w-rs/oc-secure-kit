import { randomUUID } from "node:crypto"
import { join } from "node:path"
import { atomicWrite, ensurePrivateDir, readJson, Serial, withFileLock } from "./fsutil.js"
import { validName } from "./vault.js"

/** A request by the agent for the user to enter a secret in the GUI. Contains no secret material. */
export interface SecretRequest {
  readonly id: string
  readonly entity: string
  readonly name: string
  readonly purpose: string
  readonly sessionID?: string
  readonly createdAt: string
}
interface RequestFile { format: "oc-requests/1"; requests: SecretRequest[] }

const MAX_PENDING = 100
/** Strips control characters so agent-written text cannot spoof GUI layout; keeps it short. */
export function cleanText(text: string, max = 300): string {
  return String(text ?? "").replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, " ").replace(/\s+/g, " ").trim().slice(0, max)
}

export class SecretRequests {
  readonly path: string
  #serial = new Serial()
  #listeners = new Set<(pending: SecretRequest[]) => void>()

  private constructor(path: string) { this.path = path }

  static async open(dir: string): Promise<SecretRequests> {
    await ensurePrivateDir(dir)
    return new SecretRequests(join(dir, "requests.json"))
  }

  async list(): Promise<SecretRequest[]> {
    return (await readJson<RequestFile>(this.path))?.requests ?? []
  }

  /** Adds a request, or returns the pending one for the same secret. */
  async add(input: { entity: string; name: string; purpose: string; sessionID?: string }): Promise<SecretRequest> {
    validName("entity", input.entity); validName("secret", input.name)
    return this.#mutate(requests => {
      const existing = requests.find(item => item.entity === input.entity && item.name === input.name)
      if (existing) return existing
      if (requests.length >= MAX_PENDING) throw new Error("Too many pending secret requests; ask the user to handle or dismiss them")
      const request: SecretRequest = {
        id: randomUUID(), entity: input.entity, name: input.name, purpose: cleanText(input.purpose),
        ...(input.sessionID ? { sessionID: input.sessionID } : {}), createdAt: new Date().toISOString(),
      }
      requests.push(request)
      return request
    })
  }

  /** Removes requests for a secret (after it was filled) or by ID (dismissed). */
  remove(match: { id: string } | { entity: string; name?: string }): Promise<number> {
    return this.#mutate(requests => {
      const before = requests.length
      const keep = requests.filter(item => "id" in match ? item.id !== match.id
        : !(item.entity === match.entity && (match.name === undefined || item.name === match.name)))
      requests.splice(0, requests.length, ...keep)
      return before - keep.length
    })
  }

  onChange(listener: (pending: SecretRequest[]) => void): () => void {
    this.#listeners.add(listener)
    return () => { this.#listeners.delete(listener) }
  }

  #mutate<T>(change: (requests: SecretRequest[]) => T): Promise<T> {
    return this.#serial.run(() => withFileLock(this.path, async () => {
      const requests = (await readJson<RequestFile>(this.path))?.requests ?? []
      const before = JSON.stringify(requests)
      const result = change(requests)
      if (JSON.stringify(requests) !== before) {
        await atomicWrite(this.path, JSON.stringify({ format: "oc-requests/1", requests } satisfies RequestFile, null, 2) + "\n")
        for (const listener of this.#listeners) { try { listener([...requests]) } catch {} }
      }
      return result
    }))
  }
}
