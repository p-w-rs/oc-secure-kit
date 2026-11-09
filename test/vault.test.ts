import { test } from "node:test"
import assert from "node:assert/strict"
import { chmod, readFile, stat, writeFile } from "node:fs/promises"
import { randomBytes } from "node:crypto"
import { join } from "node:path"
import { Vault, memoryKey } from "../src/vault.js"
import { scratch } from "./helpers.js"

const SECRET = "hunter2-correct-horse-battery"

test("round-trips secrets and never writes plaintext", async () => {
  const dir = await scratch()
  const vault = await Vault.open({ dir, plugin: "oc-test" })
  await vault.set("web-1", "sudo", SECRET)
  assert.equal(await vault.get("web-1", "sudo"), SECRET)
  assert.equal(await vault.get("web-1", "missing"), undefined)
  assert.deepEqual((await vault.list()).map(({ entity, name }) => ({ entity, name })), [{ entity: "web-1", name: "sudo" }])
  assert.equal(JSON.stringify(await vault.list()).includes(SECRET), false)
  const disk = await readFile(join(dir, "vault.json"), "utf8")
  assert.equal(disk.includes(SECRET), false)
  assert.equal(disk.includes(Buffer.from(SECRET).toString("base64")), false)

  const reopened = await Vault.open({ dir, plugin: "oc-test" })
  assert.equal(await reopened.get("web-1", "sudo"), SECRET)
})

test("creates private key and vault files", async () => {
  const dir = await scratch()
  const vault = await Vault.open({ dir: join(dir, "data"), plugin: "oc-test" })
  await vault.set("a", "b", SECRET)
  for (const name of ["vault.key", "vault.json"]) assert.equal((await stat(join(dir, "data", name))).mode & 0o777, 0o600, name)
  assert.equal((await stat(join(dir, "data"))).mode & 0o777, 0o700)
  assert.match(await readFile(join(dir, "data", "vault.key"), "utf8"), /^oc-vault-key\/1\n[A-Za-z0-9+/]{43}=\n$/)
})

test("refuses a key file readable by other users", async () => {
  const dir = await scratch()
  await Vault.open({ dir, plugin: "oc-test" })
  await chmod(join(dir, "vault.key"), 0o644)
  await assert.rejects(Vault.open({ dir, plugin: "oc-test" }), /readable by other users/)
})

test("detects tampered ciphertext", async () => {
  const dir = await scratch()
  const vault = await Vault.open({ dir, plugin: "oc-test" })
  await vault.set("web-1", "sudo", SECRET)
  const file = JSON.parse(await readFile(join(dir, "vault.json"), "utf8"))
  const data = Buffer.from(file.entries[0].data, "base64"); data[0]! ^= 1
  file.entries[0].data = data.toString("base64")
  await writeFile(join(dir, "vault.json"), JSON.stringify(file))
  await assert.rejects(vault.get("web-1", "sudo"), /failed authentication/)
})

test("ciphertexts are bound to their entity and name", async () => {
  const dir = await scratch()
  const vault = await Vault.open({ dir, plugin: "oc-test" })
  await vault.set("web-1", "sudo", SECRET)
  await vault.set("web-2", "sudo", "other-secret-value")
  const file = JSON.parse(await readFile(join(dir, "vault.json"), "utf8"))
  file.entries[0].entity = "web-2"; file.entries[1].entity = "web-1"
  await writeFile(join(dir, "vault.json"), JSON.stringify(file))
  await assert.rejects(vault.get("web-2", "sudo"), /failed authentication/)
})

test("rejects a vault encrypted under a different key", async () => {
  const dir = await scratch()
  await (await Vault.open({ dir, plugin: "oc-test" })).set("a", "b", SECRET)
  await assert.rejects(Vault.open({ dir, plugin: "oc-test", key: memoryKey(randomBytes(32)) }), /different key/)
  await assert.rejects(Vault.open({ dir, plugin: "oc-other" }), /belongs to oc-test/)
})

test("sees changes made by another instance and loses no concurrent writes", async () => {
  const dir = await scratch()
  const [a, b] = await Promise.all([Vault.open({ dir, plugin: "oc-test" }), Vault.open({ dir, plugin: "oc-test" })])
  await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? a : b).set("m", `s${i}`, `${SECRET}-${i}`)))
  assert.equal((await a.list()).length, 20)
  assert.equal(await b.get("m", "s7"), `${SECRET}-7`)
  let changed = 0
  b.onChange(() => changed++)
  await a.delete("m", "s7")
  assert.equal(await b.has("m", "s7"), false)
  assert.ok(changed >= 1)
})

test("rename, delete entity and import", async () => {
  const dir = await scratch()
  const vault = await Vault.open({ dir, plugin: "oc-test" })
  await vault.set("old", "sudo", SECRET)
  await vault.set("old", "env:TOKEN", "token-value-123")
  await vault.renameEntity("old", "new")
  assert.equal(await vault.get("new", "sudo"), SECRET)
  assert.equal(await vault.has("old", "sudo"), false)

  await vault.importValues([{ entity: "new", name: "sudo", value: "replaced-value" }, { entity: "x", name: "y", value: "value-xy" }])
  assert.equal(await vault.get("new", "sudo"), "replaced-value")
  assert.equal(await vault.get("new", "env:TOKEN"), "token-value-123")
  await vault.importValues([{ entity: "new", name: "only", value: "only-value" }], ["new"])
  assert.deepEqual((await vault.list("new")).map(item => item.name), ["only"])
  assert.equal(await vault.deleteEntity("x"), 1)
  assert.deepEqual((await vault.values()).map(item => item.value), ["only-value"])
})

test("validates names and values", async () => {
  const vault = await Vault.open({ dir: await scratch(), plugin: "oc-test" })
  await assert.rejects(vault.set("../etc", "x", SECRET), /Invalid entity/)
  await assert.rejects(vault.set("a", "has space", SECRET), /Invalid secret/)
  await assert.rejects(vault.set("a", "b", ""), /non-empty/)
  await assert.rejects(vault.set("a", "b", "x".repeat(70_000)), /exceeds/)
})
