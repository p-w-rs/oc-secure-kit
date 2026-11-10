import { randomBytes } from "node:crypto"
import { mkdir, readdir, readFile, rm, stat, writeFile } from "node:fs/promises"
import { dirname, join } from "node:path"
import { ensurePrivateDir } from "./fsutil.js"

/** How long per-command files outlive the command (background jobs may still be connecting). */
export const RUN_DIR_GRACE_MS = 30_000
const STALE_MS = 15 * 60_000
/** A directory whose creating process is still alive is kept this long (long builds, transfers, sessions). */
const LIVE_OWNER_MS = 7 * 24 * 60 * 60_000
const OWNER = ".owner"

const alive = (pid: number) => {
  try { process.kill(pid, 0); return true } catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM" }
}

/** A private directory of files for one shell command (configs, keys, helper scripts). Removed afterwards. */
export class RunDir {
  private constructor(readonly path: string) {}

  static async create(base: string): Promise<RunDir> {
    await ensurePrivateDir(base)
    const path = join(base, `${Date.now().toString(36)}-${randomBytes(6).toString("hex")}`)
    await mkdir(path, { mode: 0o700 })
    await writeFile(join(path, OWNER), String(process.pid), { mode: 0o600 })
    return new RunDir(path)
  }

  /**
   * Removes leftovers of commands that never finished (crash, killed server). Directories created by a process that
   * is still running (e.g. this OpenCode server, across plugin reloads) belong to commands that may still be running
   * and are kept. Never throws.
   */
  static async sweep(base: string, now = Date.now()): Promise<void> {
    try {
      for (const name of await readdir(base)) {
        const path = join(base, name)
        try {
          const age = now - (await stat(path)).mtimeMs
          if (age <= STALE_MS) continue
          const owner = Number.parseInt(await readFile(join(path, OWNER), "utf8").catch(() => ""), 10)
          if (Number.isSafeInteger(owner) && owner > 0 && alive(owner) && age <= LIVE_OWNER_MS) continue
          await rm(path, { recursive: true, force: true })
        } catch {}
      }
    } catch {}
  }

  file(name: string): string { return join(this.path, name) }

  /** Writes a new private file (0600, or 0700 for scripts). Subdirectories are created as needed. */
  async write(name: string, content: string, mode = 0o600): Promise<string> {
    const path = this.file(name)
    await mkdir(dirname(path), { recursive: true, mode: 0o700 })
    await writeFile(path, content, { mode, flag: "wx" })
    return path
  }

  async remove(): Promise<void> { await rm(this.path, { recursive: true, force: true }) }

  /** Removes the directory after the grace period, without keeping the process alive. */
  removeLater(ms = RUN_DIR_GRACE_MS): void {
    setTimeout(() => { void this.remove().catch(() => {}) }, ms).unref()
  }
}
