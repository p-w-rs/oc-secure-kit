import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { after } from "node:test"

const created: string[] = []
after(async () => { await Promise.all(created.map(dir => rm(dir, { recursive: true, force: true }))) })

/** A fresh private temp directory, removed after the test file finishes. */
export async function scratch(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "secure-kit-"))
  created.push(dir)
  return dir
}
