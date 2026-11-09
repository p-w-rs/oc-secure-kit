// Builds the vendorable tarball into .local/pack and prints its SHA-256.
// Plugins copy it with their own `pixi run vendor-kit <path>` task.
import { createHash } from "node:crypto"
import { spawnSync } from "node:child_process"
import { mkdir, readFile } from "node:fs/promises"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const out = join(root, ".local", "pack")
await mkdir(out, { recursive: true })
const result = spawnSync("npm", ["pack", "--json", "--pack-destination", out, "--cache", ".local/npm-cache"], { cwd: root, encoding: "utf8" })
if (result.status !== 0) { process.stderr.write(result.stderr); process.exit(result.status ?? 1) }
const [info] = JSON.parse(result.stdout)
const file = join(out, info.filename)
const sha256 = createHash("sha256").update(await readFile(file)).digest("hex")
console.log(`${file}\nsha256 ${sha256}`)
