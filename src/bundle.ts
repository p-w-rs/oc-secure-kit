import { createCipheriv, createDecipheriv, randomBytes, scrypt } from "node:crypto"
import { validName } from "./vault.js"

export const BUNDLE_FORMAT = "oc-bundle/1"
export const MIN_PASSPHRASE_LENGTH = 10
const MAX_BUNDLE_BYTES = 64 * 1024 * 1024

export interface KdfParams { readonly name: "scrypt"; readonly N: number; readonly r: number; readonly p: number; readonly salt: string }
export interface BundleHeader {
  readonly format: typeof BUNDLE_FORMAT
  readonly plugin: string
  readonly schemaVersion: number
  readonly createdAt: string
  readonly kdf: KdfParams
  readonly cipher: { readonly name: "aes-256-gcm"; readonly iv: string }
}
export interface BundleEnvelope extends BundleHeader { readonly ciphertext: string }

/** Default cost: N=2^17 (≈128 MiB, a fraction of a second). Tests may lower it; decryption enforces bounds. */
export const DEFAULT_COST = { N: 2 ** 17, r: 8, p: 1 } as const
const LIMITS = { minN: 2 ** 12, maxN: 2 ** 20, maxR: 16, maxP: 4 }

function derive(passphrase: string, salt: Buffer, { N, r, p }: { N: number; r: number; p: number }): Promise<Buffer> {
  return new Promise((done, fail) => scrypt(passphrase.normalize("NFC"), salt, 32, { N, r, p, maxmem: 160 * N * r + 32 * 1024 * 1024 },
    (error, key) => error ? fail(error) : done(key)))
}

/** Stable JSON (sorted keys) of the header, authenticated as associated data so no header field can be altered. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(",")}}`
  }
  return JSON.stringify(value)
}

export async function encryptBundle(
  input: { plugin: string; schemaVersion: number; payload: unknown },
  passphrase: string,
  options: { cost?: { N: number; r: number; p: number }; now?: Date } = {},
): Promise<string> {
  validName("plugin", input.plugin)
  if (!Number.isSafeInteger(input.schemaVersion) || input.schemaVersion < 1) throw new Error("schemaVersion must be a positive integer")
  if (typeof passphrase !== "string" || [...passphrase].length < MIN_PASSPHRASE_LENGTH) throw new Error(`Export passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`)
  const cost = options.cost ?? DEFAULT_COST
  const salt = randomBytes(16)
  const iv = randomBytes(12)
  const header: BundleHeader = {
    format: BUNDLE_FORMAT, plugin: input.plugin, schemaVersion: input.schemaVersion,
    createdAt: (options.now ?? new Date()).toISOString(),
    kdf: { name: "scrypt", ...cost, salt: salt.toString("base64") },
    cipher: { name: "aes-256-gcm", iv: iv.toString("base64") },
  }
  const key = await derive(passphrase, salt, cost)
  try {
    const cipher = createCipheriv("aes-256-gcm", key, iv)
    cipher.setAAD(Buffer.from(canonical(header)))
    const data = Buffer.concat([cipher.update(JSON.stringify(input.payload), "utf8"), cipher.final(), cipher.getAuthTag()])
    const envelope: BundleEnvelope = { ...header, ciphertext: data.toString("base64") }
    return JSON.stringify(envelope, null, 2) + "\n"
  } finally { key.fill(0) }
}

/** Reads the unencrypted header (plugin, version, date) without the passphrase, for an import preview. */
export function inspectBundle(text: string): BundleHeader {
  if (typeof text !== "string" || text.length > MAX_BUNDLE_BYTES) throw new Error("Bundle is missing or too large")
  let envelope: BundleEnvelope
  try { envelope = JSON.parse(text) } catch { throw new Error("Not a bundle file (invalid JSON)") }
  if (!envelope || envelope.format !== BUNDLE_FORMAT) throw new Error("Not an oc bundle, or an unsupported bundle format")
  const { kdf, cipher } = envelope
  const ok = typeof envelope.plugin === "string" && Number.isSafeInteger(envelope.schemaVersion) && envelope.schemaVersion >= 1 &&
    typeof envelope.createdAt === "string" && typeof envelope.ciphertext === "string" &&
    kdf?.name === "scrypt" && Number.isSafeInteger(kdf.N) && (kdf.N & (kdf.N - 1)) === 0 && kdf.N >= LIMITS.minN && kdf.N <= LIMITS.maxN &&
    Number.isSafeInteger(kdf.r) && kdf.r >= 1 && kdf.r <= LIMITS.maxR && Number.isSafeInteger(kdf.p) && kdf.p >= 1 && kdf.p <= LIMITS.maxP &&
    typeof kdf.salt === "string" && cipher?.name === "aes-256-gcm" && typeof cipher.iv === "string"
  if (!ok) throw new Error("Bundle header is invalid or uses unsupported parameters")
  const { ciphertext: _ciphertext, ...header } = envelope
  return header
}

export type Migrations = Readonly<Record<number, (payload: any) => unknown>>

/**
 * Decrypts and migrates a bundle to `currentVersion`. `migrations[n]` upgrades a version-n payload to n+1.
 * A wrong passphrase and a modified file produce the same error, by design of authenticated encryption.
 */
export async function decryptBundle<T>(
  text: string,
  passphrase: string,
  options: { plugin: string; currentVersion: number; migrations?: Migrations },
): Promise<{ payload: T; header: BundleHeader }> {
  const header = inspectBundle(text)
  if (header.plugin !== options.plugin) throw new Error(`This bundle was exported by ${header.plugin}, not ${options.plugin}`)
  if (header.schemaVersion > options.currentVersion) throw new Error(`This bundle needs a newer ${options.plugin} (bundle v${header.schemaVersion}, supported v${options.currentVersion})`)
  const envelope = JSON.parse(text) as BundleEnvelope
  const data = Buffer.from(envelope.ciphertext, "base64")
  if (data.length < 17) throw new Error("Wrong passphrase or damaged bundle")
  const key = await derive(passphrase, Buffer.from(header.kdf.salt, "base64"), header.kdf)
  let plaintext: string
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(header.cipher.iv, "base64"))
    decipher.setAAD(Buffer.from(canonical(header)))
    decipher.setAuthTag(data.subarray(data.length - 16))
    plaintext = Buffer.concat([decipher.update(data.subarray(0, data.length - 16)), decipher.final()]).toString("utf8")
  } catch {
    throw new Error("Wrong passphrase or damaged bundle")
  } finally { key.fill(0) }
  let payload: unknown = JSON.parse(plaintext)
  for (let version = header.schemaVersion; version < options.currentVersion; version++) {
    const migrate = options.migrations?.[version]
    if (!migrate) throw new Error(`No migration from bundle v${version} to v${version + 1}`)
    payload = migrate(payload)
  }
  return { payload: payload as T, header }
}

export type DiffStatus = "added" | "changed" | "unchanged" | "local-only"
export interface DiffItem { readonly id: string; readonly status: DiffStatus }

/** Compares keyed records for an import preview. `local-only` items are kept by merge and removed by replace-all. */
export function diffRecords(current: Readonly<Record<string, unknown>>, incoming: Readonly<Record<string, unknown>>): DiffItem[] {
  const ids = [...new Set([...Object.keys(current), ...Object.keys(incoming)])].sort()
  return ids.map(id => ({
    id,
    status: !(id in incoming) ? "local-only" : !(id in current) ? "added" : canonical(current[id]) === canonical(incoming[id]) ? "unchanged" : "changed",
  }))
}
