import { test } from "node:test"
import assert from "node:assert/strict"
import { createHash, randomBytes } from "node:crypto"
import { createServer, type IncomingMessage, type ServerResponse } from "node:http"
import { McpClient, discoverAuth, refreshGrant, startBrowserSignIn } from "../src/index.js"

/** A minimal OAuth + MCP server: issuer with a trailing slash and only OpenID metadata, like some real ones. */
async function fakeServer() {
  const codes = new Map<string, string>()
  const tokens = new Set<string>()
  const refresh = new Set<string>()
  const sessions = new Set<string>()
  const registered: (string | undefined)[] = []
  let base = ""
  const read = async (req: IncomingMessage) => { const chunks: Buffer[] = []; for await (const c of req) chunks.push(c as Buffer); return Buffer.concat(chunks).toString() }
  const send = (res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) => { res.writeHead(status, { "content-type": "application/json", ...headers }); res.end(JSON.stringify(body)) }
  const issue = () => { const a = randomBytes(8).toString("hex"), r = randomBytes(8).toString("hex"); tokens.add(a); refresh.add(r); return { access_token: a, refresh_token: r, expires_in: 300, token_type: "Bearer" } }
  const server = createServer(async (req, res) => {
    const url = new URL(req.url!, base)
    if (url.pathname === "/.well-known/oauth-protected-resource/app/mcp") return send(res, 200, { resource: `${base}/app/mcp`, authorization_servers: [`${base}/accounts/`], scopes_supported: [] })
    if (url.pathname === "/accounts/.well-known/openid-configuration") return send(res, 200, { authorization_endpoint: `${base}/accounts/authorize`, token_endpoint: `${base}/accounts/token`, registration_endpoint: `${base}/accounts/register`, scopes_supported: ["openid", "email", "offline_access"] })
    if (url.pathname === "/accounts/register") { const body = JSON.parse(await read(req)); registered.push(body.scope); return send(res, 201, { client_id: "c1", redirect_uris: body.redirect_uris }) }
    if (url.pathname === "/accounts/authorize") {
      const p = url.searchParams
      assert.equal(p.get("scope"), "openid offline_access")
      const code = randomBytes(4).toString("hex"); codes.set(code, p.get("code_challenge")!)
      res.writeHead(302, { location: `${p.get("redirect_uri")}?code=${code}&state=${p.get("state")}` }); res.end(); return
    }
    if (url.pathname === "/accounts/token") {
      const form = new URLSearchParams(await read(req))
      if (form.get("grant_type") === "authorization_code") {
        const challenge = codes.get(form.get("code")!)
        if (challenge !== createHash("sha256").update(form.get("code_verifier")!).digest("base64url")) return send(res, 400, { error: "invalid_grant" })
        return send(res, 200, issue())
      }
      if (refresh.delete(form.get("refresh_token")!)) return send(res, 200, issue())
      return send(res, 400, { error: "invalid_grant", error_description: "refresh token revoked" })
    }
    if (url.pathname === "/app/mcp") {
      if (!tokens.has(req.headers.authorization?.replace("Bearer ", "") ?? "")) return send(res, 401, {})
      const message = JSON.parse(await read(req))
      if (message.method === "initialize") { const id = randomBytes(4).toString("hex"); sessions.add(id); return send(res, 200, { jsonrpc: "2.0", id: message.id, result: { serverInfo: { name: "Fake", version: "1" }, instructions: "Be careful." } }, { "mcp-session-id": id }) }
      if (!sessions.has(String(req.headers["mcp-session-id"]))) return send(res, 404, {})
      if (!("id" in message)) { res.writeHead(202); res.end(); return }
      if (message.method === "tools/list") return send(res, 200, { jsonrpc: "2.0", id: message.id, result: { tools: [{ name: "echo", annotations: { readOnlyHint: true } }] } })
      return send(res, 200, { jsonrpc: "2.0", id: message.id, result: { content: [{ type: "text", text: JSON.stringify(message.params.arguments) }] } })
    }
    send(res, 404, {})
  })
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve))
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`
  return { mcp: `${base}/app/mcp`, sessions, tokens, registered, stop: () => new Promise(resolve => server.close(resolve)) }
}

test("MCP browser sign-in: discovery, public client, PKCE, refresh, calls", async () => {
  const fake = await fakeServer()
  try {
    const scopes = (_: readonly string[], server: readonly string[]) => server.filter(scope => ["openid", "offline_access"].includes(scope))
    const auth = await discoverAuth(fake.mcp, { scopes })
    assert.equal(auth.resource, fake.mcp)
    assert.deepEqual(auth.scopes, ["openid", "offline_access"])
    const flow = await startBrowserSignIn(fake.mcp, { clientName: "test", service: "Fake", scopes })
    const redirect = await fetch(flow.url, { redirect: "manual" })
    const page = await (await fetch(redirect.headers.get("location")!)).text()
    assert.match(page, /Signed in to Fake/)
    const { grant, client } = await flow.done
    assert.ok(grant.refreshToken && grant.expiresAt! > Date.now())
    assert.deepEqual(grant.scopes, ["openid", "offline_access"], "requested scopes when the server does not echo them")
    let token = grant.accessToken
    const mcp = new McpClient(fake.mcp, { clientName: "test", service: "Fake", authorization: async () => `Bearer ${token}`, onUnauthorized: async () => { token = (await refreshGrant(client, grant.refreshToken!)).accessToken } })
    assert.deepEqual(await mcp.initialize(), { name: "Fake", version: "1", instructions: "Be careful." })
    assert.equal((await mcp.listTools())[0]!.name, "echo")
    fake.sessions.clear()
    assert.equal((await mcp.call("echo", { a: 1 })).text, '{"a":1}', "expired session is renewed")
    fake.tokens.clear()
    assert.equal((await mcp.call("echo", { b: 2 })).text, '{"b":2}', "401 refreshes once and retries")
    await assert.rejects(refreshGrant(client, grant.refreshToken!, "Fake"), /Fake sign-in expired; sign in again \(refresh token revoked\)/)
    const cancelled = await startBrowserSignIn(fake.mcp, { clientName: "test", scopes })
    cancelled.cancel()
    await assert.rejects(cancelled.done, /cancelled/)
    const withScopes = await startBrowserSignIn(fake.mcp, { clientName: "test", scopes, registerScopes: true })
    withScopes.cancel()
    await withScopes.done.catch(() => {})
    assert.deepEqual(fake.registered, [undefined, undefined, "openid offline_access"], "scopes are registered only when asked")
  } finally { await fake.stop() }
})
