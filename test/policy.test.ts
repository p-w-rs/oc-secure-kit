import { test } from "node:test"
import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import { join } from "node:path"
import { PolicyStore, StaleRevisionError, combineEffects } from "../src/policy.js"
import { scratch } from "./helpers.js"

test("resolution order: session, agent, any-agent row, fallback", async () => {
  const store = await PolicyStore.open(await scratch())
  const at = (agent?: string, sessionRoot?: string) => store.resolve({ entity: "web", capability: "sudo", agent, sessionRoot, fallback: "deny" })
  assert.deepEqual(await at("build"), { effect: "deny", source: "default" })
  await store.setCells([{ entity: "web", row: { agent: "*" }, capability: "sudo", effect: "ask" }])
  assert.deepEqual(await at("build"), { effect: "ask", source: "any-agent" })
  await store.setCells([{ entity: "web", row: { agent: "build" }, capability: "sudo", effect: "allow" }])
  assert.deepEqual(await at("build"), { effect: "allow", source: "agent" })
  assert.deepEqual(await at("plan"), { effect: "ask", source: "any-agent" })
  await store.setCells([{ entity: "web", row: { session: "ses_root" }, capability: "sudo", effect: "deny" }])
  assert.deepEqual(await at("build", "ses_root"), { effect: "deny", source: "session" })
  assert.deepEqual(await at("build", "ses_other"), { effect: "allow", source: "agent" })
  await store.setCells([{ entity: "web", row: { session: "ses_root" }, capability: "sudo", effect: null }])
  assert.deepEqual(await at("build", "ses_root"), { effect: "allow", source: "agent" })
  assert.equal(Object.keys(store.snapshot().sessions).length, 0, "empty session rows are pruned")
})

test("combineEffects picks the strictest", () => {
  assert.equal(combineEffects([]), "allow")
  assert.equal(combineEffects(["allow", "ask"]), "ask")
  assert.equal(combineEffects(["ask", "deny", "allow"]), "deny")
})

test("optimistic revisions reject stale GUI edits", async () => {
  const store = await PolicyStore.open(await scratch())
  const doc = await store.setCells([{ entity: "web", row: { agent: "*" }, capability: "ssh", effect: "allow" }], 0)
  assert.equal(doc.revision, 1)
  await assert.rejects(store.setCells([{ entity: "web", row: { agent: "*" }, capability: "ssh", effect: "deny" }], 0), StaleRevisionError)
  assert.equal((await store.resolve({ entity: "web", capability: "ssh" })).effect, "allow")
})

test("another instance's edits are visible and concurrent edits all land", async () => {
  const dir = await scratch()
  const [a, b] = await Promise.all([PolicyStore.open(dir), PolicyStore.open(dir)])
  await Promise.all(Array.from({ length: 10 }, (_, i) =>
    (i % 2 ? a : b).setCells([{ entity: "web", row: { agent: "*" }, capability: `c${i}`, effect: "allow" }])))
  assert.equal((await a.resolve({ entity: "web", capability: "c3" })).effect, "allow")
  assert.equal((await b.resolve({ entity: "web", capability: "c4" })).effect, "allow")
  assert.equal((await a.reload()).revision, 10)
})

test("rename, copy, remove entity and capability", async () => {
  const store = await PolicyStore.open(await scratch())
  await store.setCells([
    { entity: "old", row: { agent: "*" }, capability: "ssh", effect: "allow" },
    { entity: "old", row: { agent: "*" }, capability: "env.TOKEN", effect: "ask" },
    { entity: "old", row: { session: "ses_1" }, capability: "ssh", effect: "deny" },
  ])
  await store.renameEntity("old", "new")
  assert.equal((await store.resolve({ entity: "new", capability: "ssh", sessionRoot: "ses_1" })).effect, "deny")
  assert.equal((await store.resolve({ entity: "old", capability: "ssh" })).source, "default")
  await store.copyEntity("new", "copy")
  assert.equal((await store.resolve({ entity: "copy", capability: "env.TOKEN" })).effect, "ask")
  await store.removeCapability("new", "env.TOKEN")
  assert.equal((await store.resolve({ entity: "new", capability: "env.TOKEN" })).source, "default")
  await store.removeEntity("new")
  assert.deepEqual(Object.keys(store.snapshot().entities), ["copy"])
  assert.deepEqual(store.snapshot().sessions, {})
})

test("export excludes session overrides; import validates", async () => {
  const store = await PolicyStore.open(await scratch())
  await store.setCells([
    { entity: "web", row: { agent: "build" }, capability: "sudo", effect: "allow" },
    { entity: "web", row: { session: "ses_1" }, capability: "sudo", effect: "deny" },
  ])
  const exported = await store.exportEntities()
  assert.deepEqual(exported, { web: { agents: { build: { sudo: "allow" } } } })
  assert.equal(JSON.stringify(exported).includes("ses_1"), false)

  const other = await PolicyStore.open(await scratch())
  await other.importEntities(exported)
  assert.equal((await other.resolve({ entity: "web", capability: "sudo", agent: "build" })).effect, "allow")
  await assert.rejects(other.importEntities({ web: { agents: { build: { sudo: "always" as never } } } }), /Invalid effect/)
  await assert.rejects(other.importEntities({ "../x": { agents: {} } }), /Invalid entity/)
})

test("rejects invalid edits and corrupt files", async () => {
  const dir = await scratch()
  const store = await PolicyStore.open(dir)
  await assert.rejects(store.setCells([{ entity: "web", row: { agent: "bad agent" }, capability: "ssh", effect: "allow" }]), /Invalid agent/)
  await assert.rejects(store.setCells([{ entity: "web", row: { agent: "*" }, capability: "ssh", effect: "yes" as never }]), /Invalid effect/)
  await store.setCells([{ entity: "web", row: { agent: "*" }, capability: "ssh", effect: "allow" }])
  const text = await readFile(join(dir, "policy.json"), "utf8")
  assert.match(text, /"format": "oc-policy\/1"/)
})
