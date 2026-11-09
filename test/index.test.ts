import { test } from "node:test"
import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import { FORMATS, SECURE_KIT_VERSION } from "../src/index.js"

test("exported version matches package.json", async () => {
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"))
  assert.equal(SECURE_KIT_VERSION, pkg.version)
})

test("format identifiers are versioned", () => {
  for (const id of Object.values(FORMATS)) assert.match(id, /^oc-[a-z]+\/\d+$/)
})
