import { test } from "node:test"
import assert from "node:assert/strict"
import { join } from "node:path"
import { PermissionBridge, guardDirectories, sessionRoots, type AssertInput, type EvaluateEvent, type PermissionHost } from "../src/bridge.js"
import { PolicyStore, type Effect } from "../src/policy.js"
import { scratch } from "./helpers.js"

/** Mirrors OpenCode 2.2.6 Permission.assert: configured denies first, then evaluate hooks, then prompt on ask. */
function fakeHost(options: { configuredDeny?: (action: string) => boolean; base?: Effect; reply?: "approve" | "reject" } = {}) {
  const hooks: ((event: EvaluateEvent) => Promise<void> | void)[] = []
  const prompts: AssertInput[] = []
  const host: PermissionHost = {
    async hook(_name, callback) {
      hooks.push(callback)
      return { dispose: async () => { hooks.splice(hooks.indexOf(callback), 1) } }
    },
    async assert(input) {
      if (options.configuredDeny?.(input.action)) throw new Error(`blocked by configured rule: ${input.action}`)
      const event: EvaluateEvent = { ...input, effect: options.base ?? "allow" }
      for (const hook of hooks) await hook(event)
      if (event.effect === "deny") throw new Error(event.message ?? "denied")
      if (event.effect === "ask") {
        prompts.push(input)
        if (options.reply === "reject") throw new Error("rejected by user")
      }
    },
  }
  const evaluate = async (input: Omit<EvaluateEvent, "effect">, effect: Effect = options.base ?? "allow") => {
    const event: EvaluateEvent = { ...input, effect }
    for (const hook of hooks) await hook(event)
    return event
  }
  return { host, prompts, evaluate }
}

async function setup(fallback: Effect = "ask") {
  const policy = await PolicyStore.open(await scratch())
  const parents: Record<string, string | undefined> = { child: "root", grandchild: "child" }
  const bridge = new PermissionBridge({ plugin: "oc-test", policy, root: sessionRoots(async id => parents[id]), fallback: () => fallback })
  return { policy, bridge }
}

test("table decides allow, ask (native prompt) and deny for plugin actions", async () => {
  const { policy, bridge } = await setup()
  const { host, prompts } = fakeHost({ base: "allow" })
  await bridge.install(host)
  const check = (agent = "build") => bridge.check({ sessionID: "grandchild", agent, capability: "sudo", entities: ["web"], metadata: { command: "apt update" } })

  await check()
  assert.equal(prompts.length, 1, "unset cell falls back to ask even though native rules allow")
  assert.deepEqual(prompts[0]!.save, [])

  await policy.setCells([{ entity: "web", row: { agent: "build" }, capability: "sudo", effect: "allow" }])
  await check()
  assert.equal(prompts.length, 1)

  await policy.setCells([{ entity: "web", row: { session: "root" }, capability: "sudo", effect: "deny" }])
  await assert.rejects(check(), /Denied by the oc-test permissions table \(sudo on web\)/)
})

test("rejecting the native prompt rejects the check", async () => {
  const { bridge } = await setup()
  const { host } = fakeHost({ reply: "reject" })
  await bridge.install(host)
  await assert.rejects(bridge.check({ sessionID: "root", capability: "ssh", entities: ["web"] }), /rejected by user/)
})

test("configured native deny still wins over an allow cell", async () => {
  const { policy, bridge } = await setup()
  const { host } = fakeHost({ configuredDeny: action => action === "oc-test.sudo" })
  await bridge.install(host)
  await policy.setCells([{ entity: "web", row: { agent: "*" }, capability: "sudo", effect: "allow" }])
  await assert.rejects(bridge.check({ sessionID: "root", capability: "sudo", entities: ["web"] }), /configured rule/)
})

test("multiple entities combine to the strictest effect", async () => {
  const { policy, bridge } = await setup("allow")
  const { host, evaluate } = fakeHost()
  await bridge.install(host)
  await policy.setCells([{ entity: "b", row: { agent: "*" }, capability: "ssh", effect: "ask" }])
  assert.equal((await evaluate({ sessionID: "root", action: "oc-test.ssh", resources: ["a", "b"] })).effect, "ask")
})

test("ignores other actions and fails closed on bad input", async () => {
  const { bridge } = await setup("allow")
  const { host, evaluate } = fakeHost()
  await bridge.install(host)
  assert.equal((await evaluate({ sessionID: "root", action: "oc-other.ssh", resources: ["a"] }, "ask")).effect, "ask")
  assert.equal((await evaluate({ sessionID: "root", action: "read", resources: ["a"] }, "allow")).effect, "allow")
  const bad = await evaluate({ sessionID: "root", action: "oc-test.bad name", resources: ["a"] })
  assert.equal(bad.effect, "deny")
  assert.match(bad.message!, /permissions unavailable/)
})

test("effect() reports the decision without prompting", async () => {
  const { policy, bridge } = await setup()
  await policy.setCells([{ entity: "web", row: { agent: "plan" }, capability: "ssh", effect: "deny" }])
  assert.deepEqual(await bridge.effect({ sessionID: "child", agent: "plan", capability: "ssh", entity: "web" }), { effect: "deny", source: "agent" })
  await assert.rejects(new PermissionBridge({ plugin: "oc-test", policy, root: async id => id }).check({ sessionID: "s", capability: "ssh", entities: ["web"] }), /not installed/)
})

test("sessionRoots follows parents, caches and rejects cycles", async () => {
  let lookups = 0
  const parents: Record<string, string | undefined> = { c: "b", b: "a", x: "y", y: "x" }
  const root = sessionRoots(async id => { lookups++; return parents[id] })
  assert.equal(await root("c"), "a")
  const before = lookups
  assert.equal(await root("b"), "a")
  assert.equal(lookups, before, "cached")
  await assert.rejects(root("x"), /Invalid session ancestry/)
})

test("guardDirectories denies native file tools inside private directories only", async () => {
  const dir = await scratch()
  const { host, evaluate } = fakeHost()
  await guardDirectories(host, "oc-test", [dir])
  const at = async (action: string, resource: string) => (await evaluate({ sessionID: "s", action, resources: [resource] })).effect
  assert.equal(await at("read", join(dir, "vault.key")), "deny")
  assert.equal(await at("edit", join(dir, "policy.json")), "deny")
  assert.equal(await at("external_directory", `${dir}/*`), "deny")
  assert.equal(await at("read", join(dir, "sub", "..", "..", "elsewhere")), "allow")
  assert.equal(await at("read", `${dir}-sibling/file`), "allow")
  assert.equal(await at("read", "relative/path"), "allow")
  assert.equal(await at("shell", join(dir, "vault.key")), "allow", "shell is not intercepted (documented limit)")
})

/** A pushable event stream like OpenCode's event.subscribe. */
function eventStream() {
  const queue: unknown[] = []
  let wake: (() => void) | undefined
  let subscriptions = 0
  return {
    push(event: unknown) { queue.push(event); wake?.() },
    get subscriptions() { return subscriptions },
    host: {
      subscribe({ signal }: { types: string[]; signal: AbortSignal }) {
        subscriptions++
        return (async function* () {
          while (!signal.aborted) {
            while (queue.length) yield queue.shift() as never
            await new Promise<void>(resolve => { wake = resolve; signal.addEventListener("abort", () => resolve(), { once: true }) })
          }
        })()
      },
    },
  }
}
const settle = () => new Promise(resolve => setTimeout(resolve, 20))

test("'Allow always' on the native prompt sets the asking agent's cells to allow", async () => {
  const { policy, bridge } = await setup()
  const events = eventStream()
  const registration = bridge.followReplies(events.host)
  events.push({ type: "permission.asked", data: { id: "p1", sessionID: "root", action: "oc-test.use", resources: ["env:A", "env:B"], metadata: { agent: "build" } } })
  events.push({ type: "permission.replied", data: { sessionID: "root", requestID: "p1", reply: "always" } })
  await settle()
  for (const entity of ["env:A", "env:B"]) assert.deepEqual(await policy.resolve({ entity, capability: "use", agent: "build" }), { effect: "allow", source: "agent" })
  assert.equal((await policy.resolve({ entity: "env:A", capability: "use", agent: "plan" })).source, "default", "other agents unaffected")

  events.push({ type: "permission.asked", data: { id: "p2", sessionID: "root", action: "oc-test.sudo", resources: ["web"], metadata: { agent: "build" } } })
  events.push({ type: "permission.replied", data: { sessionID: "root", requestID: "p2", reply: "once" } })
  events.push({ type: "permission.asked", data: { id: "p3", sessionID: "root", action: "read", resources: ["x"] } })
  events.push({ type: "permission.replied", data: { sessionID: "root", requestID: "p3", reply: "always" } })
  await settle()
  assert.equal((await policy.resolve({ entity: "web", capability: "sudo", agent: "build" })).source, "default", "once does not change the table")
  assert.equal(Object.keys(policy.snapshot().entities).sort().join(), "env:A,env:B", "other plugins' and native prompts are ignored")
  await registration.dispose()
})

test("prompts carry the agent so 'Allow always' knows the row", async () => {
  const { bridge } = await setup()
  const { host, prompts } = fakeHost()
  await bridge.install(host)
  await bridge.check({ sessionID: "root", agent: "plan", capability: "ssh", entities: ["web"], metadata: { command: "ssh web" } })
  assert.deepEqual(prompts[0]!.metadata, { command: "ssh web", agent: "plan" })
})

test("child entities inherit unset cells from their parent", async () => {
  const policy = await PolicyStore.open(await scratch())
  const bridge = new PermissionBridge({ plugin: "oc-test", policy, root: async id => id, fallback: () => "allow", parent: e => e.includes("@") ? e.split("@")[0] : undefined })
  await policy.setCells([{ entity: "work", row: { agent: "*" }, capability: "push", effect: "ask" }])
  assert.equal((await bridge.effect({ sessionID: "s", capability: "push", entity: "work@acme" })).effect, "ask")
  await policy.setCells([{ entity: "work@acme", row: { agent: "*" }, capability: "push", effect: "deny" }])
  assert.equal((await bridge.effect({ sessionID: "s", capability: "push", entity: "work@acme" })).effect, "deny")
  assert.equal((await bridge.effect({ sessionID: "s", capability: "read", entity: "work@acme" })).effect, "allow")
})
