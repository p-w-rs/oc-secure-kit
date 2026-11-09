import { test } from "node:test"
import assert from "node:assert/strict"
import { decryptBundle, diffRecords, encryptBundle, inspectBundle } from "../src/bundle.js"

// Low cost keeps tests fast; production uses DEFAULT_COST.
const cost = { N: 2 ** 12, r: 8, p: 1 }
const PASS = "correct horse battery"
const payload = { machines: { web: { host: "web.example" } }, secrets: [{ entity: "web", name: "sudo", value: "pw-123456" }] }

test("round-trips and hides contents", async () => {
  const text = await encryptBundle({ plugin: "oc-test", schemaVersion: 1, payload }, PASS, { cost })
  assert.equal(text.includes("pw-123456"), false)
  assert.equal(text.includes("web.example"), false)
  const header = inspectBundle(text)
  assert.equal(header.plugin, "oc-test")
  assert.equal(header.schemaVersion, 1)
  const result = await decryptBundle(text, PASS, { plugin: "oc-test", currentVersion: 1 })
  assert.deepEqual(result.payload, payload)
})

test("default cost works", async () => {
  const text = await encryptBundle({ plugin: "oc-test", schemaVersion: 1, payload: { a: 1 } }, PASS)
  assert.equal(inspectBundle(text).kdf.N, 2 ** 17)
  assert.deepEqual((await decryptBundle(text, PASS, { plugin: "oc-test", currentVersion: 1 })).payload, { a: 1 })
})

test("wrong passphrase and tampering give the same error", async () => {
  const text = await encryptBundle({ plugin: "oc-test", schemaVersion: 1, payload }, PASS, { cost })
  const options = { plugin: "oc-test", currentVersion: 2, migrations: { 1: (p: unknown) => p } }
  await assert.rejects(decryptBundle(text, "wrong passphrase!", options), /Wrong passphrase or damaged bundle/)

  const envelope = JSON.parse(text)
  const data = Buffer.from(envelope.ciphertext, "base64"); data[3]! ^= 0xff
  await assert.rejects(decryptBundle(JSON.stringify({ ...envelope, ciphertext: data.toString("base64") }), PASS, options), /Wrong passphrase/)
  await assert.rejects(decryptBundle(JSON.stringify({ ...envelope, createdAt: "2000-01-01T00:00:00.000Z" }), PASS, options), /Wrong passphrase/)
  await assert.rejects(decryptBundle(JSON.stringify({ ...envelope, schemaVersion: 2 }), PASS, options), /Wrong passphrase/, "header is authenticated")
  await assert.rejects(decryptBundle(JSON.stringify({ ...envelope, ciphertext: "AAAA" }), PASS, options), /Wrong passphrase/)
})

test("rejects another plugin's bundle, newer versions and bad headers", async () => {
  const text = await encryptBundle({ plugin: "oc-test", schemaVersion: 3, payload }, PASS, { cost })
  await assert.rejects(decryptBundle(text, PASS, { plugin: "oc-other", currentVersion: 3 }), /exported by oc-test/)
  await assert.rejects(decryptBundle(text, PASS, { plugin: "oc-test", currentVersion: 2 }), /needs a newer oc-test/)
  const envelope = JSON.parse(text)
  assert.throws(() => inspectBundle("not json"), /invalid JSON/)
  assert.throws(() => inspectBundle(JSON.stringify({ ...envelope, format: "x" })), /unsupported bundle format/)
  assert.throws(() => inspectBundle(JSON.stringify({ ...envelope, kdf: { ...envelope.kdf, N: 2 ** 24 } })), /unsupported parameters/, "caps attacker-chosen cost")
  assert.throws(() => inspectBundle(JSON.stringify({ ...envelope, kdf: { ...envelope.kdf, N: 3000 } })), /unsupported parameters/)
})

test("migrates old payloads step by step", async () => {
  const text = await encryptBundle({ plugin: "oc-test", schemaVersion: 1, payload: { name: "web" } }, PASS, { cost })
  const result = await decryptBundle<{ label: string; tags: string[] }>(text, PASS, {
    plugin: "oc-test", currentVersion: 3,
    migrations: { 1: (p: { name: string }) => ({ label: p.name }), 2: (p: { label: string }) => ({ ...p, tags: [] }) },
  })
  assert.deepEqual(result.payload, { label: "web", tags: [] })
  assert.equal(result.header.schemaVersion, 1)
  await assert.rejects(decryptBundle(text, PASS, { plugin: "oc-test", currentVersion: 2 }), /No migration from bundle v1/)
})

test("requires a reasonable passphrase", async () => {
  await assert.rejects(encryptBundle({ plugin: "oc-test", schemaVersion: 1, payload }, "short", { cost }), /at least 10/)
})

test("diffRecords classifies entries for the import preview", () => {
  assert.deepEqual(diffRecords(
    { same: { a: 1, b: 2 }, edited: { a: 1 }, mine: {} },
    { same: { b: 2, a: 1 }, edited: { a: 2 }, fresh: {} },
  ), [
    { id: "edited", status: "changed" },
    { id: "fresh", status: "added" },
    { id: "mine", status: "local-only" },
    { id: "same", status: "unchanged" },
  ])
})
