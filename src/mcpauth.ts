import { createHash, randomBytes } from "node:crypto"
import { createServer, type Server } from "node:http"

/**
 * Browser sign-in to a remote MCP server (OAuth 2.1 as in the MCP authorization spec): protected-resource metadata
 * (RFC 9728), authorization-server metadata (RFC 8414 / OpenID discovery), dynamic client registration as a public
 * client (RFC 7591, no secret), PKCE (S256), a loopback callback, resource indicators (RFC 8707) and refresh.
 */

export interface AuthServer {
  readonly resource: string
  readonly authorizationEndpoint: string
  readonly tokenEndpoint: string
  readonly registrationEndpoint: string
  readonly scopes: readonly string[]
}

export interface Grant {
  readonly accessToken: string
  readonly refreshToken?: string
  /** Epoch milliseconds. */
  readonly expiresAt?: number
  readonly scopes: string[]
}

/** What a refresh needs; stored next to the tokens. */
export interface OAuthClient { readonly clientId: string; readonly tokenEndpoint: string; readonly resource: string }

export interface DiscoverOptions {
  /** Which advertised scopes to request; default all. */
  readonly scopes?: (advertised: readonly string[], server: readonly string[]) => readonly string[]
  /** Name used in error messages, e.g. "Atlassian". */
  readonly service?: string
}

const json = async (response: Response, what: string) => {
  const text = await response.text()
  let data: Record<string, unknown>
  try { data = JSON.parse(text) } catch { throw new Error(`${what}: ${response.status} ${text.slice(0, 200)}`) }
  return data
}

async function serverMetadata(issuer: string, service: string): Promise<Record<string, unknown>> {
  const url = new URL(issuer)
  const path = url.pathname.replace(/\/+$/, "")
  const candidates = [
    `${url.origin}/.well-known/oauth-authorization-server${path}`,
    `${url.origin}${path}/.well-known/oauth-authorization-server`,
    `${url.origin}/.well-known/openid-configuration${path}`,
    `${url.origin}${path}/.well-known/openid-configuration`,
  ]
  let last = ""
  for (const candidate of [...new Set(candidates)]) {
    try {
      const response = await fetch(candidate)
      if (!response.ok) { last = `${response.status} at ${candidate}`; continue }
      const data = await json(response, `${service} authorization metadata`)
      if (data.authorization_endpoint && data.token_endpoint) return data
    } catch (error) { last = (error as Error).message }
  }
  throw new Error(`${service}: could not read the sign-in server's metadata (${last})`)
}

/** Reads how to sign in to an MCP server. */
export async function discoverAuth(mcp: string, options: DiscoverOptions = {}): Promise<AuthServer> {
  const service = options.service ?? "The server"
  const url = new URL(mcp)
  const path = url.pathname.replace(/\/+$/, "")
  let resourceMeta: Record<string, unknown> | undefined
  for (const candidate of [`${url.origin}/.well-known/oauth-protected-resource${path}`, `${url.origin}/.well-known/oauth-protected-resource`]) {
    const response = await fetch(candidate)
    if (response.ok) { resourceMeta = await json(response, `${service} resource metadata`); break }
  }
  if (!resourceMeta) throw new Error(`${service} does not publish sign-in metadata for ${mcp}`)
  const issuer = (resourceMeta.authorization_servers as string[] | undefined)?.[0]
  if (!issuer) throw new Error(`${service} did not name an authorization server`)
  const server = await serverMetadata(issuer, service)
  if (!server.registration_endpoint) throw new Error(`${service}'s sign-in server does not allow app self-registration; it cannot be used without a registered app`)
  const advertised = (resourceMeta.scopes_supported as string[] | undefined) ?? []
  const serverScopes = (server.scopes_supported as string[] | undefined) ?? []
  const scopes = options.scopes ? options.scopes(advertised, serverScopes) : advertised
  return {
    resource: String(resourceMeta.resource ?? mcp),
    authorizationEndpoint: String(server.authorization_endpoint),
    tokenEndpoint: String(server.token_endpoint),
    registrationEndpoint: String(server.registration_endpoint),
    scopes: [...scopes],
  }
}

const grantOf = (data: Record<string, unknown>, requested: readonly string[] = []): Grant => ({
  accessToken: String(data.access_token),
  ...(typeof data.refresh_token === "string" && { refreshToken: data.refresh_token }),
  ...(typeof data.expires_in === "number" && { expiresAt: Date.now() + data.expires_in * 1000 }),
  scopes: typeof data.scope === "string" ? data.scope.split(/\s+/).filter(Boolean) : [...requested],
})

export async function refreshGrant(client: OAuthClient, refreshToken: string, service = "The server"): Promise<Grant> {
  const data = await json(await fetch(client.tokenEndpoint, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams({ grant_type: "refresh_token", client_id: client.clientId, refresh_token: refreshToken, resource: client.resource }),
  }), `${service} token refresh`)
  if (!data.access_token) throw new Error(`${service} sign-in expired; sign in again (${data.error_description ?? data.error ?? "no token"})`)
  return grantOf(data)
}

const b64 = (buffer: Buffer) => buffer.toString("base64url")
const escape = (text: string) => text.replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;" })[c]!)

export interface BrowserSignIn {
  /** Open this in a browser on the same computer as the OpenCode server. */
  readonly url: string
  readonly expiresAt: number
  /** Resolves with the grant once the user approves; rejects on error, cancel or timeout. */
  readonly done: Promise<{ grant: Grant; client: OAuthClient }>
  /** Completes from a pasted redirect URL (when the browser runs on another computer). */
  complete(redirectUrl: string): void
  cancel(): void
}

export interface BrowserSignInOptions extends DiscoverOptions {
  readonly clientName: string
  readonly timeoutMs?: number
  /** Extra authorization parameters, e.g. { prompt: "consent" }. */
  readonly authorizeParams?: Record<string, string>
  /** Also send the requested scopes when registering the client (some servers limit a client to its registered scopes). */
  readonly registerScopes?: boolean
}

/** Starts a browser sign-in as a public client. Works with any identity provider the server offers (SSO etc.). */
export async function startBrowserSignIn(mcp: string, options: BrowserSignInOptions): Promise<BrowserSignIn> {
  const service = options.service ?? "The server"
  const auth = await discoverAuth(mcp, options)
  const server: Server = createServer()
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve))
  const redirectUri = `http://127.0.0.1:${(server.address() as { port: number }).port}/callback`
  let clientId: string
  try {
    const registration = await json(await fetch(auth.registrationEndpoint, {
      method: "POST", headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ client_name: options.clientName, redirect_uris: [redirectUri], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none", ...(options.registerScopes && auth.scopes.length && { scope: auth.scopes.join(" ") }) }),
    }), `${service} client registration`)
    if (!registration.client_id) throw new Error(`${service} refused the sign-in client: ${registration.error_description ?? registration.error ?? "no client id"}`)
    clientId = String(registration.client_id)
  } catch (error) { server.close(); throw error }
  const verifier = b64(randomBytes(32)), state = b64(randomBytes(16))
  const url = new URL(auth.authorizationEndpoint)
  for (const [key, value] of Object.entries({
    client_id: clientId, response_type: "code", redirect_uri: redirectUri, ...(auth.scopes.length && { scope: auth.scopes.join(" ") }), state,
    code_challenge: b64(createHash("sha256").update(verifier).digest()), code_challenge_method: "S256", resource: auth.resource, ...options.authorizeParams,
  })) url.searchParams.set(key, value)

  const timeoutMs = options.timeoutMs ?? 15 * 60_000
  let settle!: (code: string) => void, fail!: (error: Error) => void
  const code = new Promise<string>((resolve, reject) => { settle = resolve; fail = reject })
  const timer = setTimeout(() => fail(new Error("The sign-in was not finished in time; start again")), timeoutMs)
  const handle = (target: URL) => {
    const params = target.searchParams
    if (params.get("state") !== state) { fail(new Error("Sign-in response did not match (state); start again")); return false }
    const value = params.get("code")
    if (value) { settle(value); return true }
    fail(new Error(`Sign-in was not approved: ${params.get("error_description") ?? params.get("error") ?? "unknown"}`))
    return false
  }
  const name = escape(options.service ?? "the service")
  server.on("request", (req, res) => {
    if (!req.url?.startsWith("/callback")) { res.writeHead(404); res.end(); return }
    const ok = handle(new URL(req.url, redirectUri))
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" })
    res.end(`<!doctype html><title>${name} sign-in</title><body style="font:16px system-ui;margin:3em">${ok ? `<h2>Signed in to ${name}.</h2><p>You can close this tab and return to OpenCode.</p>` : "<h2>Sign-in did not complete.</h2><p>Return to OpenCode and try again.</p>"}</body>`)
  })
  const done = code.then(async value => {
    const data = await json(await fetch(auth.tokenEndpoint, {
      method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: new URLSearchParams({ grant_type: "authorization_code", client_id: clientId, code: value, redirect_uri: redirectUri, code_verifier: verifier, resource: auth.resource }),
    }), `${service} token exchange`)
    if (!data.access_token) throw new Error(`${service} did not issue a token: ${data.error_description ?? data.error ?? "unknown"}`)
    return { grant: grantOf(data, auth.scopes), client: { clientId, tokenEndpoint: auth.tokenEndpoint, resource: auth.resource } }
  }).finally(() => { clearTimeout(timer); server.close() })
  done.catch(() => {})
  return {
    url: url.href, expiresAt: Date.now() + timeoutMs, done,
    complete: redirectUrl => { try { handle(new URL(redirectUrl)) } catch { fail(new Error("That is not the address the browser was sent to after sign-in")) } },
    cancel: () => fail(new Error("Sign-in cancelled")),
  }
}

// ------------------------------------------------------------------ MCP client (Streamable HTTP)

export interface McpToolInfo { readonly name: string; readonly title?: string; readonly description?: string; readonly inputSchema?: unknown; readonly annotations?: Record<string, unknown> }
export interface McpCallResult { readonly text: string; readonly isError: boolean; readonly structured?: unknown }
export interface McpServerInfo { readonly name?: string; readonly version?: string; readonly instructions?: string }

export class HttpStatusError extends Error {
  constructor(message: string, readonly status: number) { super(message) }
}

export interface McpClientOptions {
  /** Authorization header value (refreshing as needed). */
  readonly authorization: () => Promise<string>
  /** Called once on 401 before retrying (e.g. force a token refresh). */
  readonly onUnauthorized?: () => Promise<void>
  readonly clientName: string
  readonly clientVersion?: string
  /** Name used in error messages. */
  readonly service?: string
}

export class McpClient {
  #session?: string
  #initialized?: Promise<void>
  #info: McpServerInfo = {}
  #id = 0
  constructor(private readonly url: string, private readonly options: McpClientOptions) {}

  get service(): string { return this.options.service ?? "Server" }
  /** Server name, version and instructions from the last initialize. */
  get info(): McpServerInfo { return this.#info }

  async #post(body: Record<string, unknown>, retried = false): Promise<Record<string, unknown> | undefined> {
    const response = await fetch(this.url, {
      method: "POST",
      headers: {
        authorization: await this.options.authorization(), "content-type": "application/json", accept: "application/json, text/event-stream",
        "mcp-protocol-version": "2025-06-18", ...(this.#session && { "mcp-session-id": this.#session }),
      },
      body: JSON.stringify({ jsonrpc: "2.0", ...body }),
    })
    const session = response.headers.get("mcp-session-id")
    if (session) this.#session = session
    const text = await response.text()
    if (response.status === 401 && !retried && this.options.onUnauthorized) { await this.options.onUnauthorized(); return this.#post(body, true) }
    if (response.status === 404 && this.#session && !retried && body.method !== "initialize") {
      // Session expired on the server: start a new one and retry once.
      this.reset()
      await this.#ensure()
      return this.#post(body, true)
    }
    if (!response.ok && response.status !== 202) throw new HttpStatusError(`${this.service} ${response.status}: ${text.slice(0, 300)}`, response.status)
    if (!text.trim()) return undefined
    const lines = text.split("\n").filter(line => line.startsWith("data:")).map(line => line.slice(5).trim()).filter(Boolean)
    const messages = (lines.length ? lines : [text]).map(line => JSON.parse(line) as Record<string, unknown>)
    const reply = messages.find(message => "id" in message && message.id === body.id) ?? messages.at(-1)
    if (reply?.error) {
      const error = reply.error as { message?: string; code?: number }
      throw new Error(`${this.service}: ${error.message ?? JSON.stringify(error)}`)
    }
    return reply?.result as Record<string, unknown> | undefined
  }

  reset(): void { this.#session = undefined; this.#initialized = undefined }

  #ensure(): Promise<void> {
    this.#initialized ??= (async () => {
      const result = await this.#post({ id: ++this.#id, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: this.options.clientName, version: this.options.clientVersion ?? "0.0.0" } } })
      const server = (result?.serverInfo ?? {}) as { name?: string; version?: string }
      this.#info = { ...(server.name && { name: server.name }), ...(server.version && { version: server.version }), ...(typeof result?.instructions === "string" && { instructions: result.instructions }) }
      await this.#post({ method: "notifications/initialized" })
    })().catch(error => { this.#initialized = undefined; throw error })
    return this.#initialized
  }

  async initialize(): Promise<McpServerInfo> { await this.#ensure(); return this.#info }

  async listTools(): Promise<McpToolInfo[]> {
    await this.#ensure()
    const tools: McpToolInfo[] = []
    let cursor: string | undefined
    for (let page = 0; page < 20; page++) {
      const result = await this.#post({ id: ++this.#id, method: "tools/list", params: cursor ? { cursor } : {} })
      tools.push(...((result?.tools as McpToolInfo[] | undefined) ?? []))
      cursor = result?.nextCursor as string | undefined
      if (!cursor) break
    }
    return tools
  }

  async call(name: string, args: Record<string, unknown>): Promise<McpCallResult> {
    await this.#ensure()
    const result = await this.#post({ id: ++this.#id, method: "tools/call", params: { name, arguments: args } })
    const content = (result?.content as { type: string; text?: string }[] | undefined) ?? []
    return {
      text: content.map(part => part.type === "text" ? part.text ?? "" : `[${part.type}]`).join("\n"),
      isError: result?.isError === true,
      ...(result?.structuredContent !== undefined && { structured: result.structuredContent }),
    }
  }
}
