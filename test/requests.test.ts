import { test } from "node:test"
import assert from "node:assert/strict"
import { SecretRequests, cleanText } from "../src/requests.js"
import { scratch } from "./helpers.js"

test("adds, dedupes, lists and removes requests", async () => {
  const requests = await SecretRequests.open(await scratch())
  let notified = 0
  requests.onChange(() => notified++)
  const first = await requests.add({ entity: "web", name: "sudo", purpose: "run apt update", sessionID: "ses_1" })
  const again = await requests.add({ entity: "web", name: "sudo", purpose: "different" })
  assert.equal(again.id, first.id)
  await requests.add({ entity: "web", name: "env:TOKEN", purpose: "deploy" })
  assert.equal((await requests.list()).length, 2)
  assert.equal(notified, 2)
  assert.equal(await requests.remove({ entity: "web", name: "sudo" }), 1)
  assert.equal(await requests.remove({ id: "missing" }), 0)
  assert.equal(await requests.remove({ entity: "web" }), 1)
  assert.deepEqual(await requests.list(), [])
})

test("sanitizes agent-written purpose text", () => {
  assert.equal(cleanText("line1\nline2\u202e\u0007  spaced"), "line1 line2 spaced")
  assert.equal(cleanText("x".repeat(500)).length, 300)
})

test("validates names", async () => {
  const requests = await SecretRequests.open(await scratch())
  await assert.rejects(requests.add({ entity: "a b", name: "x", purpose: "" }), /Invalid entity/)
})
