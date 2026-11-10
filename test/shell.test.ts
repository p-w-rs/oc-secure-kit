import { test } from "node:test"
import assert from "node:assert/strict"
import { readdir, rm, stat, utimes, writeFile } from "node:fs/promises"
import { basename } from "node:path"
import { Redactor } from "../src/redact.js"
import { RunDir } from "../src/rundir.js"
import { ShellSupplier, appendNote } from "../src/shell.js"
import { scratch } from "./helpers.js"

const ctx = (id: string) => ({ tool: "shell", sessionID: "s", agent: "build", messageID: "m", id })

test("supplies env only to the matching shell, masks and annotates its output", async () => {
  const redactor = new Redactor(); redactor.set("tok", "secret-token-value")
  const base = await scratch()
  const supplier = new ShellSupplier({
    plugin: "oc-test", redactor, warn: () => {},
    prepare: async (command, caller) => command.includes("$TOK") ? { env: { TOK: "secret-token-value", WD: caller.workdir ?? "" }, notes: ["used TOK"], secrets: true, runDir: await RunDir.create(base) } : undefined,
    annotate: command => command.startsWith("plain") ? "tip" : undefined,
  })
  await supplier.before({ ...ctx("a"), input: { command: "echo $TOK", workdir: "sub" } })
  await supplier.before({ ...ctx("b"), input: { command: "plain" } })
  const other = { command: "plain", env: {} as Record<string, string | undefined> }
  supplier.create(other)
  const mine = { command: "echo $TOK", env: {} as Record<string, string | undefined> }
  supplier.create(mine)
  assert.deepEqual(other.env, {})
  assert.deepEqual(mine.env, { TOK: "secret-token-value", WD: "sub" })
  const done = { tool: "shell", id: "a", input: { command: "echo $TOK" }, status: "completed" as const, result: { content: [{ type: "text", text: "secret-token-value\n" }] } }
  supplier.after(done)
  assert.deepEqual(done.result, { content: [{ type: "text", text: "[REDACTED:tok]\n[oc-test] used TOK" }] })
  const plain = { tool: "shell", id: "b", input: { command: "plain" }, status: "completed" as const, result: { content: "x" } }
  supplier.after(plain)
  assert.deepEqual(plain.result, { content: "x\n[oc-test] tip" })
  assert.equal((await readdir(base)).length, 1, "run dir kept for the grace period")
  supplier.dispose()
})

test("a failing prepare never blocks the command", async () => {
  const warnings: string[] = []
  const supplier = new ShellSupplier({ plugin: "oc-test", redactor: new Redactor(), warn: m => warnings.push(m), prepare: async () => { throw new Error("boom") } })
  await supplier.before({ ...ctx("a"), input: { command: "x" } })
  const event = { command: "x", env: {} }
  supplier.create(event)
  assert.deepEqual(event.env, {})
  assert.equal(warnings.length, 1)
})

test("RunDir writes private files and scripts", async () => {
  const run = await RunDir.create(await scratch())
  assert.equal((await stat(await run.write("a/b.txt", "x"))).mode & 0o777, 0o600)
  assert.equal((await stat(await run.write("s.sh", "#!/bin/sh\n", 0o700))).mode & 0o777, 0o700)
  assert.deepEqual(appendNote({ content: "" }, "n", "p"), { content: "[p] n" })
})

test("RunDir.sweep keeps directories of a live process, removes stale ones of dead or unknown owners", async () => {
  const base = await scratch()
  const live = await RunDir.create(base)
  const dead = await RunDir.create(base)
  await writeFile(dead.file(".owner"), "2147483646")
  const legacy = await RunDir.create(base)
  await rm(legacy.file(".owner"))
  const fresh = await RunDir.create(base)
  await Promise.all([live, dead, legacy].map(run => utimes(run.path, new Date(Date.now() - 16 * 60_000), new Date(Date.now() - 16 * 60_000))))
  await RunDir.sweep(base, Date.now())
  const left = await readdir(base)
  assert.ok(left.includes(basename(live.path)), "live owner kept (a long command may still use it)")
  assert.ok(left.includes(basename(fresh.path)), "recent kept")
  assert.ok(!left.includes(basename(dead.path)), "dead owner removed")
  assert.ok(!left.includes(basename(legacy.path)), "no owner removed")
})

test("mask patterns and onDone: output masked synchronously, onDone awaited before cleanup", async () => {
  const base = await scratch()
  const order: string[] = []
  const supplier = new ShellSupplier({
    plugin: "oc-test", redactor: new Redactor(), warn: () => {},
    prepare: async () => ({ env: {}, notes: [], secrets: true, mask: [/eyJ[\w-]+\.[\w-]+\.[\w-]+/], runDir: await RunDir.create(base), onDone: async status => { order.push(`done:${status}`) } }),
  })
  await supplier.before({ ...ctx("a"), input: { command: "az account get-access-token" } })
  const event = { tool: "shell", id: "a", input: { command: "az account get-access-token" }, status: "completed" as const, result: { content: [{ type: "text", text: '{"accessToken": "eyJabc.eyJdef.sig-123"}' }] } }
  const pending = supplier.after(event)
  assert.deepEqual(event.result, { content: [{ type: "text", text: '{"accessToken": "[REDACTED:token]"}' }] }, "masked before any await")
  await pending
  assert.deepEqual(order, ["done:completed"])
  supplier.dispose()
})
