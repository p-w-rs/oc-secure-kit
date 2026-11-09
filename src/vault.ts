import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from "node:crypto"
import { open, readFile, stat } from "node:fs/promises"
import { dirname, join } from "node:path"
import { atomicWrite, ensurePrivateDir, readJson, Serial, withFileLock } from "./fsutil.js"

export const VAULT_FORMAT = "oc-vault/1"
const KEY_FORMAT = "oc-vault-key/1"
const NAME = /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,127}$/
export const MAX_SECRET_BYTES = 64 * 1024

/** Where the 32-byte vault key comes from. The vault file format is the same for every source. */
export interface KeySource {
  readonly description: string
  load(): Promise<Buffer>
}

/**
 * A random key in a 0600 file, created on first use. Protects copies of the vault file and backups;
 * it does not protect against processes running as the same OS user, which can read the key.
 */
export function fileKey(path: string): KeySource {
  return {
    description: `key file ${path}`,
    async load() {
      await ensurePrivateDir(dirname(path))
      try {
        const handle = await open(path, "wx", 0o600)
        try { await handle.writeFile(`${KEY_FORMAT}\n${randomBytes(32).toString("base64")}\n`); await handle.sync() }
        finally { await handle.close() }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error
      }
      const info = await stat(path)
      if ((info.mode & 0o077) !== 0) throw new Error(`Vault key ${path} is readable by other users; run: chmod 600 '${path}'`)
      const [format, encoded] = (await readFile(path, "utf8")).trim().split("\n")
      const key = Buffer.from(encoded ?? "", "base64")
      if (format !== KEY_FORMAT || key.length !== 32) throw new Error(`Invalid vault key file: ${path}`)
      return key
    },
  }
}

/** A key held only in memory, e.g. derived from a passphrase. */
export function memoryKey(key: Buffer, description = "in-memory key"): KeySource {
  if (key.length !== 32) throw new Error("Vault key must be 32 bytes")
  const copy = Buffer.from(key)
  return { description, load: async () => copy }
}

export interface SecretMeta {
  readonly entity: string
  readonly name: string
  readonly updatedAt: string
}
export interface SecretValue {
  readonly entity: string
  readonly name: string
  readonly value: string
}
interface Entry extends SecretMeta { iv: string; data: string; tag: string }
interface VaultFile { format: string; plugin: string; keyId: string; entries: Entry[] }

export function validName(kind: string, value: string): string {
  if (typeof value !== "string" || !NAME.test(value)) throw new Error(`Invalid ${kind} name ${JSON.stringify(value)}: use 1-128 letters, digits and . _ : @ + -`)
  return value
}

/** Encrypted secret storage: one AES-256-GCM ciphertext per (entity, name), bound to both as associated data. */
export class Vault {
  readonly plugin: string
  readonly path: string
  #key: Buffer
  #keyId: string
  #file: VaultFile
  #stamp = ""
  #serial = new Serial()
  #listeners = new Set<() => void>()

  private constructor(plugin: string, path: string, key: Buffer, file: VaultFile) {
    this.plugin = plugin
    this.path = path
    this.#key = key
    this.#keyId = keyId(key)
    this.#file = file
  }

  /** Opens `<dir>/vault.json`, using `<dir>/vault.key` unless another key source is given. */
  static async open(options: { dir: string; plugin: string; key?: KeySource }): Promise<Vault> {
    validName("plugin", options.plugin)
    await ensurePrivateDir(options.dir)
    const key = await (options.key ?? fileKey(join(options.dir, "vault.key"))).load()
    const vault = new Vault(options.plugin, join(options.dir, "vault.json"), key,
      { format: VAULT_FORMAT, plugin: options.plugin, keyId: keyId(key), entries: [] })
    await vault.#refresh()
    return vault
  }

  /** Secret metadata only; never values. */
  async list(entity?: string): Promise<SecretMeta[]> {
    await this.#refresh()
    return this.#file.entries
      .filter(entry => entity === undefined || entry.entity === entity)
      .map(({ entity, name, updatedAt }) => ({ entity, name, updatedAt }))
  }

  async has(entity: string, name: string): Promise<boolean> {
    await this.#refresh()
    return this.#file.entries.some(entry => entry.entity === entity && entry.name === name)
  }

  async get(entity: string, name: string): Promise<string | undefined> {
    await this.#refresh()
    const entry = this.#file.entries.find(item => item.entity === entity && item.name === name)
    return entry && this.#decrypt(entry)
  }

  async set(entity: string, name: string, value: string): Promise<void> {
    validName("entity", entity); validName("secret", name)
    if (typeof value !== "string" || value.length === 0) throw new Error("Secret value must be a non-empty string")
    if (Buffer.byteLength(value) > MAX_SECRET_BYTES) throw new Error(`Secret value exceeds ${MAX_SECRET_BYTES} bytes`)
    await this.#mutate(file => {
      file.entries = file.entries.filter(entry => !(entry.entity === entity && entry.name === name))
      file.entries.push(this.#encrypt(entity, name, value))
    })
  }

  async delete(entity: string, name: string): Promise<boolean> {
    let removed = false
    await this.#mutate(file => {
      const before = file.entries.length
      file.entries = file.entries.filter(entry => !(entry.entity === entity && entry.name === name))
      removed = file.entries.length !== before
    })
    return removed
  }

  async deleteEntity(entity: string): Promise<number> {
    let removed = 0
    await this.#mutate(file => {
      const before = file.entries.length
      file.entries = file.entries.filter(entry => entry.entity !== entity)
      removed = before - file.entries.length
    })
    return removed
  }

  /** Re-encrypts an entity's secrets under a new entity name (names are bound into each ciphertext). */
  async renameEntity(from: string, to: string): Promise<void> {
    validName("entity", to)
    await this.#mutate(file => {
      if (from !== to && file.entries.some(entry => entry.entity === to)) throw new Error(`Entity ${to} already has secrets`)
      file.entries = file.entries.map(entry => entry.entity === from ? this.#encrypt(to, entry.name, this.#decrypt(entry), entry.updatedAt) : entry)
    })
  }

  /** Every decrypted value, for output redaction. */
  async values(): Promise<SecretValue[]> {
    await this.#refresh()
    return this.#file.entries.map(entry => ({ entity: entry.entity, name: entry.name, value: this.#decrypt(entry) }))
  }

  /** Replaces or merges secrets from an import. `replaceEntities` lists entities whose existing secrets are dropped first. */
  async importValues(values: readonly SecretValue[], replaceEntities: readonly string[] = []): Promise<void> {
    for (const item of values) { validName("entity", item.entity); validName("secret", item.name) }
    await this.#mutate(file => {
      const replace = new Set(replaceEntities)
      file.entries = file.entries.filter(entry => !replace.has(entry.entity) &&
        !values.some(item => item.entity === entry.entity && item.name === entry.name))
      for (const item of values) file.entries.push(this.#encrypt(item.entity, item.name, item.value))
    })
  }

  /** Called after any change made by this process or detected on disk. */
  onChange(listener: () => void): () => void {
    this.#listeners.add(listener)
    return () => { this.#listeners.delete(listener) }
  }

  #encrypt(entity: string, name: string, value: string, updatedAt = new Date().toISOString()): Entry {
    const iv = randomBytes(12)
    const cipher = createCipheriv("aes-256-gcm", this.#key, iv)
    cipher.setAAD(this.#aad(entity, name))
    const data = Buffer.concat([cipher.update(value, "utf8"), cipher.final()])
    return { entity, name, updatedAt, iv: iv.toString("base64"), data: data.toString("base64"), tag: cipher.getAuthTag().toString("base64") }
  }

  #decrypt(entry: Entry): string {
    try {
      const decipher = createDecipheriv("aes-256-gcm", this.#key, Buffer.from(entry.iv, "base64"))
      decipher.setAAD(this.#aad(entry.entity, entry.name))
      decipher.setAuthTag(Buffer.from(entry.tag, "base64"))
      return Buffer.concat([decipher.update(Buffer.from(entry.data, "base64")), decipher.final()]).toString("utf8")
    } catch {
      throw new Error(`Vault entry ${entry.entity}/${entry.name} failed authentication (tampered or wrong key)`)
    }
  }

  #aad(entity: string, name: string): Buffer {
    return Buffer.from(`${VAULT_FORMAT}\0${this.plugin}\0${entity}\0${name}`, "utf8")
  }

  async #refresh(): Promise<void> {
    let stamp: string
    try { const info = await stat(this.path); stamp = `${info.mtimeMs}:${info.size}:${info.ino}` }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
      stamp = "missing"
    }
    if (stamp === this.#stamp) return
    const file = stamp === "missing" ? undefined : await readJson<VaultFile>(this.path)
    const next = file ?? { format: VAULT_FORMAT, plugin: this.plugin, keyId: this.#keyId, entries: [] }
    if (next.format !== VAULT_FORMAT) throw new Error(`Unsupported vault format ${JSON.stringify(next.format)} in ${this.path}`)
    if (next.plugin !== this.plugin) throw new Error(`${this.path} belongs to ${next.plugin}, not ${this.plugin}`)
    if (!Array.isArray(next.entries)) throw new Error(`Corrupt vault: ${this.path}`)
    if (next.entries.length > 0 && !sameId(next.keyId, this.#keyId)) {
      throw new Error(`${this.path} was encrypted with a different key than ${this.#keyId.slice(0, 8)}…; restore the matching vault.key or import a bundle instead`)
    }
    const changed = this.#stamp !== "" && this.#stamp !== stamp
    this.#file = next
    this.#stamp = stamp
    if (changed) this.#emit()
  }

  #mutate(change: (file: VaultFile) => void): Promise<void> {
    return this.#serial.run(() => withFileLock(this.path, async () => {
      this.#stamp = ""
      await this.#refresh()
      const file: VaultFile = { ...this.#file, keyId: this.#keyId, entries: [...this.#file.entries] }
      change(file)
      file.entries.sort((a, b) => a.entity.localeCompare(b.entity) || a.name.localeCompare(b.name))
      await atomicWrite(this.path, JSON.stringify(file, null, 2) + "\n")
      this.#stamp = ""
      await this.#refresh()
      this.#emit()
    }))
  }

  #emit(): void {
    for (const listener of this.#listeners) { try { listener() } catch {} }
  }
}

function keyId(key: Buffer): string {
  return createHmac("sha256", key).update("oc-vault key id").digest("hex").slice(0, 32)
}
function sameId(a: string, b: string): boolean {
  return typeof a === "string" && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b))
}
