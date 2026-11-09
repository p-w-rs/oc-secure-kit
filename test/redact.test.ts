import { test } from "node:test"
import assert from "node:assert/strict"
import { Redactor, installRedaction, patternsFor } from "../src/redact.js"

const SECRET = "s3cr3t-Value_with/chars+=?"
const make = () => { const r = new Redactor(); r.set("web/sudo", SECRET); return r }

test("masks raw, URL-encoded, JSON-escaped and hex forms", () => {
  const r = make()
  assert.equal(r.redact(`pw=${SECRET}!`), "pw=[REDACTED:web/sudo]!")
  assert.equal(r.redact(encodeURIComponent(SECRET)), "[REDACTED:web/sudo]")
  assert.equal(r.redact(Buffer.from(SECRET).toString("hex")), "[REDACTED:web/sudo]")
  assert.equal(r.redact(Buffer.from(SECRET).toString("hex").toUpperCase()), "[REDACTED:web/sudo]")
  const quoted = new Redactor(); quoted.set("q", 'a"b\\c-long-value')
  assert.equal(quoted.redact(JSON.stringify({ v: 'a"b\\c-long-value' })), '{"v":"[REDACTED:q]"}')
})

test("masks base64 of the secret at any alignment inside larger blobs", () => {
  const r = make()
  for (const prefix of ["", "x", "xy", "xyz", "prefix:"]) {
    for (const suffix of ["", "!", "!!", "trailing"]) {
      const blob = Buffer.from(prefix + SECRET + suffix).toString("base64")
      const masked = r.redact(blob)
      assert.match(masked, /\[REDACTED:web\/sudo\]/, `prefix=${prefix} suffix=${suffix}`)
      const urlSafe = blob.replaceAll("+", "-").replaceAll("/", "_")
      assert.match(r.redact(urlSafe), /\[REDACTED:web\/sudo\]/, `url-safe prefix=${prefix}`)
    }
  }
})

test("a secret's own decoded text is masked even when encoded with env-var preamble", () => {
  const r = make()
  const output = Buffer.from(`TOKEN=${SECRET}\nPATH=/usr/bin\n`).toString("base64")
  assert.match(r.redact(output), /REDACTED/)
})

test("skips too-short values and longer secrets win over contained ones", () => {
  assert.deepEqual(patternsFor("x", "short"), [])
  const r = new Redactor()
  r.set("inner", "abcdefgh")
  r.set("outer", "abcdefgh-and-more")
  assert.equal(r.redact("abcdefgh-and-more abcdefgh"), "[REDACTED:outer] [REDACTED:inner]")
  r.delete("outer")
  assert.equal(r.redact("abcdefgh-and-more"), "[REDACTED:inner]-and-more")
  r.replaceAll([])
  assert.equal(r.size, 0)
  assert.equal(r.redact("abcdefgh"), "abcdefgh")
})

test("redactDeep walks plain objects and arrays only", () => {
  const r = make()
  const date = new Date(0)
  const result = r.redactDeep({ output: `x ${SECRET}`, list: [SECRET, 3, null], nested: { date, ok: true } })
  assert.deepEqual(result, { output: "x [REDACTED:web/sudo]", list: ["[REDACTED:web/sudo]", 3, null], nested: { date, ok: true } })
})

async function capture(r: Redactor, tools: Parameters<typeof installRedaction>[2], onError?: (e: unknown) => void) {
  let hook: ((event: any) => void | Promise<void>) | undefined
  await installRedaction({ hook: async (_name, callback) => { hook = callback; return { dispose: async () => {} } } }, r, tools, onError)
  return hook!
}

test("installRedaction rewrites the plugin's own tool results and errors", async () => {
  const hook = await capture(make(), new Set(["machine_exec"]))
  const done = { tool: "machine_exec", status: "completed" as const, result: { output: `token ${SECRET}`, metadata: { exit: 0 } } }
  await hook(done)
  assert.deepEqual(done.result, { output: "token [REDACTED:web/sudo]", metadata: { exit: 0 } })
  const failed = { tool: "machine_exec", status: "error" as const, error: new Error(`failed with ${SECRET}`) }
  await hook(failed)
  assert.equal(failed.error.message, "failed with [REDACTED:web/sudo]")
})

test("native tool output is untouched unless redaction of all tools is opted in", async () => {
  const native = () => ({ tool: "read", status: "completed" as const, result: { output: `GH_TOKEN=${SECRET}` } })
  const scoped = native()
  await (await capture(make(), new Set(["machine_exec"])))(scoped)
  assert.equal(scoped.result.output, `GH_TOKEN=${SECRET}`)
  const all = native()
  await (await capture(make(), "all"))(all)
  assert.equal(all.result.output, "GH_TOKEN=[REDACTED:web/sudo]")
})

test("installRedaction never throws into the host", async () => {
  const errors: unknown[] = []
  const hook = await capture(make(), () => { throw new Error("boom") }, error => errors.push(error))
  const event = { tool: "x", status: "completed" as const, result: { output: SECRET } }
  await hook(event)
  assert.equal(event.result.output, SECRET)
  assert.equal(errors.length, 1)
})
