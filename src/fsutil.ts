import { randomBytes } from "node:crypto"
import { chmod, mkdir, open, readFile, rename, stat, unlink } from "node:fs/promises"
import { homedir } from "node:os"
import { dirname, join } from "node:path"

/** Per-plugin data directory: `$XDG_DATA_HOME/<plugin>` (default `~/.local/share/<plugin>`) on macOS and Linux. */
export function pluginDataDir(plugin: string, override?: string): string {
  if (override) {
    if (!override.startsWith("/")) throw new Error(`${plugin}: dataDirectory must be an absolute path`)
    return override
  }
  return join(process.env.XDG_DATA_HOME || join(homedir(), ".local", "share"), plugin)
}

/** Creates `dir` (and parents) and makes sure the final directory is private to the owner. */
export async function ensurePrivateDir(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true, mode: 0o700 })
  const info = await stat(dir)
  if (!info.isDirectory()) throw new Error(`Not a directory: ${dir}`)
  if ((info.mode & 0o077) !== 0) await chmod(dir, 0o700)
}

/** Writes via a private temp file, fsync and rename, so readers see the old or the new file, never a partial one. */
export async function atomicWrite(path: string, data: string | Uint8Array, mode = 0o600): Promise<void> {
  await ensurePrivateDir(dirname(path))
  const temporary = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`
  const handle = await open(temporary, "wx", mode)
  try {
    await handle.writeFile(data)
    await handle.sync()
  } catch (error) {
    await handle.close()
    await unlink(temporary).catch(() => {})
    throw error
  }
  await handle.close()
  try { await rename(temporary, path) }
  catch (error) { await unlink(temporary).catch(() => {}); throw error }
}

export async function readJson<T>(path: string): Promise<T | undefined> {
  let text: string
  try { text = await readFile(path, "utf8") }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error }
  try { return JSON.parse(text) as T }
  catch { throw new Error(`Corrupt JSON file: ${path}`) }
}

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true }
  catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM" }
}

/**
 * Cross-process exclusive lock using an `O_EXCL` lock file next to `path`.
 * A lock whose owner process is gone, or that is older than `staleMs`, is broken.
 */
export async function withFileLock<T>(path: string, fn: () => Promise<T>, { timeoutMs = 10_000, staleMs = 30_000 } = {}): Promise<T> {
  const lock = `${path}.lock`
  await ensurePrivateDir(dirname(lock))
  const deadline = Date.now() + timeoutMs
  for (;;) {
    try {
      const handle = await open(lock, "wx", 0o600)
      await handle.writeFile(JSON.stringify({ pid: process.pid, at: Date.now() }))
      await handle.close()
      break
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error
      let stale = false
      try {
        const owner = JSON.parse(await readFile(lock, "utf8")) as { pid?: number; at?: number }
        stale = (typeof owner.pid === "number" && owner.pid !== process.pid && !alive(owner.pid)) ||
          (typeof owner.at === "number" && Date.now() - owner.at > staleMs)
      } catch {
        // Unreadable or half-written lock file: treat as stale once it is old enough.
        try { stale = Date.now() - (await stat(lock)).mtimeMs > staleMs } catch { continue }
      }
      if (stale) { await unlink(lock).catch(() => {}); continue }
      if (Date.now() > deadline) throw new Error(`Timed out waiting for lock ${lock}`)
      await sleep(25 + Math.random() * 50)
    }
  }
  try { return await fn() }
  finally { await unlink(lock).catch(() => {}) }
}

/** Runs async tasks one at a time, in call order. */
export class Serial {
  #tail: Promise<unknown> = Promise.resolve()
  run<T>(task: () => Promise<T>): Promise<T> {
    const next = this.#tail.then(task, task)
    this.#tail = next.catch(() => {})
    return next
  }
}
