// Installs locked npm dependencies with the Pixi-provided Node/npm only.
// Skips work when package.json + lockfile + platform are unchanged since the last install.
import { createHash } from "node:crypto"
import { spawnSync } from "node:child_process"
import { readFile, rename, unlink, writeFile } from "node:fs/promises"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const refresh = process.argv.includes("--refresh")
const read = async name => { try { return await readFile(join(root, name), "utf8") } catch (error) { if (error.code === "ENOENT") return undefined; throw error } }

const manifest = await read("package.json")
const lockName = (await read("npm-shrinkwrap.json")) !== undefined ? "npm-shrinkwrap.json" : "package-lock.json"
const lock = await read(lockName)
const npm = (args) => {
  const result = spawnSync(process.platform === "win32" ? "npm.cmd" : "npm", args, { cwd: root, stdio: "inherit" })
  if (result.error || result.status !== 0) throw result.error || new Error(`npm ${args[0]} failed (${result.status})`)
}

if (refresh || lock === undefined) {
  // Explicit: (re)resolve the lockfile. Never happens implicitly once a lock exists.
  npm(["install", "--ignore-scripts", "--no-audit", "--no-fund", "--cache", ".local/npm-cache"])
  // Plugins ship npm-shrinkwrap.json so installed snapshots keep exact versions; libraries keep package-lock.json.
  if (process.argv.includes("--shrinkwrap")) npm(["shrinkwrap"])
  console.log(`Resolved dependencies and wrote ${process.argv.includes("--shrinkwrap") ? "npm-shrinkwrap.json" : lockName}. Review and commit it.`)
  process.exit(0)
}

const fingerprint = createHash("sha256").update(manifest).update(lock)
  .update(`${process.platform}-${process.arch}-node${process.versions.node.split(".")[0]}`).digest("hex")
const stamp = join(root, "node_modules", ".oc-deps.json")
try { if (JSON.parse(await readFile(stamp, "utf8")).fingerprint === fingerprint) process.exit(0) } catch {}

const guard = join(root, ".deps.lock")
try { await writeFile(guard, String(process.pid), { flag: "wx", mode: 0o600 }) }
catch (error) {
  if (error.code === "EEXIST") throw new Error(`Dependency install already running (${guard}). If a prior run crashed, confirm it stopped before removing the lock.`)
  throw error
}
try {
  npm(["ci", "--ignore-scripts", "--no-audit", "--no-fund", "--cache", ".local/npm-cache"])
  const temporary = `${stamp}.${process.pid}.tmp`
  await writeFile(temporary, JSON.stringify({ fingerprint }) + "\n")
  await rename(temporary, stamp)
  console.log("Locked dependencies are ready.")
} finally { await unlink(guard) }
