// @orkestia/auth — "Sign in with Orkestia" for apps built on the Orkestia
// platform. Browser PKCE authorization-code flow against the hosted login
// (login.orkestia.dev) + token exchange / local JWT verification against the
// identity API (workflow-api.orkestia.dev). No secret in the browser.
//
// Quickstart:
//   const auth = createOrkestiaAuth({ clientKey: 'orkestia_…' })
//   // on a "Sign in" click:        await auth.signIn()
//   // on your redirect_uri page:   const session = await auth.handleCallback()
//   // anywhere:                     auth.getSession() / auth.signOut()

export interface OrkestiaAuthConfig {
  /** Public client key from identity.app.provision (PKCE — safe in the browser). */
  clientKey: string
  /** Hosted login origin. Default: https://login.orkestia.dev */
  loginUrl?: string
  /** Identity API origin (token + jwks). Default: https://workflow-api.orkestia.dev */
  identityApi?: string
  /** Where login returns. Default: location.origin + '/'. Must be registered for the client. */
  redirectUri?: string
  /** Where to stash the verifier/state + session. Default: sessionStorage. */
  storage?: Storage
  /**
   * Where the hidden `prompt=none` renewal iframe returns. Default: redirectUri.
   * Must be registered for the client. Point at a lightweight page to make
   * silent renewals faster (the full app never has to boot in the iframe).
   */
  silentRedirectUri?: string
  /** Refresh a near-expiry access token in the background. Default: true. */
  autoRenew?: boolean
  /** Refresh this many seconds before the access token expires. Default: 60. */
  renewSkewSeconds?: number
  /** Max wait for a silent renewal before it's treated as login-required. Default: 10000ms. */
  silentTimeoutMs?: number
  /**
   * Called when a silent renewal fails and the user must fully re-authenticate
   * (session revoked/expired). The local session is already cleared and the
   * auto-renew loop stopped when this fires — respond by calling signIn().
   */
  onRequiresLogin?: (error: OrkestiaLoginRequiredError) => void
}

/**
 * Thrown when a silent renewal cannot produce a fresh token — the identity
 * session was revoked (`identity.end-user.session.revoke`) or expired, or the
 * `prompt=none` authorization otherwise failed. Signals the app to run a full
 * `signIn()`; the SDK deliberately does not retry, so this never loops.
 */
export class OrkestiaLoginRequiredError extends Error {
  /** Machine-readable cause: an OIDC error code (`login_required`, …) or `timeout`. */
  readonly reason: string
  constructor(reason: string, message?: string) {
    super(message ?? `silent renewal failed (${reason}) — full login required`)
    this.name = 'OrkestiaLoginRequiredError'
    this.reason = reason
  }
}

export interface OrkestiaClaims {
  sub?: string
  email?: string
  exp?: number
  iss?: string
  aud?: string
  end_user_uuid?: string
  [k: string]: unknown
}

export interface OrkestiaSession {
  token: string
  claims: OrkestiaClaims
  email?: string
  endUserUuid?: string
}

const DEFAULT_LOGIN = 'https://login.orkestia.dev'
const DEFAULT_API = 'https://workflow-api.orkestia.dev'
const K_VERIFIER = 'orkestia.pkce.verifier'
const K_STATE = 'orkestia.pkce.state'
const K_SESSION = 'orkestia.session'

function b64url(bytes: ArrayBuffer): string {
  let s = ''
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function fromB64url(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(pad + '='.repeat((4 - (pad.length % 4)) % 4))
  // Allocate over a plain ArrayBuffer (not ArrayBufferLike) so the result stays
  // assignable to WebCrypto's BufferSource under TS 5.7+ generic typed arrays.
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
function randomVerifier(): string {
  return b64url(crypto.getRandomValues(new Uint8Array(32)).buffer)
}
async function challengeFor(verifier: string): Promise<string> {
  return b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))
}
function decodeJwt(token: string): OrkestiaClaims | null {
  try {
    return JSON.parse(new TextDecoder().decode(fromB64url(token.split('.')[1]))) as OrkestiaClaims
  } catch {
    return null
  }
}

export function createOrkestiaAuth(config: OrkestiaAuthConfig) {
  const loginUrl = (config.loginUrl ?? DEFAULT_LOGIN).replace(/\/$/, '')
  const api = (config.identityApi ?? DEFAULT_API).replace(/\/$/, '')
  const store = config.storage ?? sessionStorage
  const redirectUri = config.redirectUri ?? (typeof location !== 'undefined' ? location.origin + '/' : '')
  const silentRedirectUri = config.silentRedirectUri ?? redirectUri
  const autoRenew = config.autoRenew ?? true
  const renewSkewMs = (config.renewSkewSeconds ?? 60) * 1000
  const silentTimeoutMs = config.silentTimeoutMs ?? 10_000
  let renewInFlight: Promise<OrkestiaSession> | null = null
  let renewTimer: ReturnType<typeof setTimeout> | null = null

  /** Begin sign-in: build PKCE, then redirect to the hosted login. */
  async function signIn(): Promise<void> {
    const verifier = randomVerifier()
    const challenge = await challengeFor(verifier)
    const state = b64url(crypto.getRandomValues(new Uint8Array(16)).buffer)
    store.setItem(K_VERIFIER, verifier)
    store.setItem(K_STATE, state)
    const q = new URLSearchParams({
      client_key: config.clientKey,
      redirect_uri: redirectUri,
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
    })
    location.href = `${loginUrl}/authorize?${q.toString()}`
  }

  /**
   * Call on your redirect_uri page. Reads ?code&state, exchanges the code for a
   * token, stores + returns the session. Returns null if there's no code in the URL.
   */
  async function handleCallback(): Promise<OrkestiaSession | null> {
    const params = new URLSearchParams(location.search)
    const code = params.get('code')
    if (!code) return null
    const returnedState = params.get('state')
    const expected = store.getItem(K_STATE)
    if (expected && returnedState !== expected) throw new Error('state mismatch (possible CSRF)')
    const verifier = store.getItem(K_VERIFIER)
    if (!verifier) throw new Error('missing code_verifier (storage cleared?)')

    const res = await fetch(`${api}/api/auth/end-user/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, code_verifier: verifier }),
    })
    const data = (await res.json()) as { token?: string; message?: string; error?: string }
    if (!res.ok || !data.token) throw new Error(data.message || data.error || 'token exchange failed')

    store.removeItem(K_VERIFIER)
    store.removeItem(K_STATE)
    history.replaceState(null, '', location.pathname) // strip the code from the URL
    return setSession(data.token)
  }

  function setSession(token: string): OrkestiaSession {
    const claims = decodeJwt(token) ?? {}
    const session: OrkestiaSession = { token, claims, email: claims.email, endUserUuid: claims.end_user_uuid }
    store.setItem(K_SESSION, JSON.stringify(session))
    scheduleRenew(claims)
    return session
  }

  function clearRenewTimer(): void {
    if (renewTimer !== null) {
      clearTimeout(renewTimer)
      renewTimer = null
    }
  }

  /** Arm a background renewal to fire `renewSkewSeconds` before the token expires. */
  function scheduleRenew(claims: OrkestiaClaims): void {
    clearRenewTimer()
    if (!autoRenew || typeof setTimeout === 'undefined' || !claims.exp) return
    const delay = Math.max(0, claims.exp * 1000 - renewSkewMs - Date.now())
    renewTimer = setTimeout(() => {
      // On failure onRequiresLogin has already fired and the session is cleared;
      // swallow here so a rejected background renewal never becomes an unhandled
      // rejection and — crucially — never reschedules (no silent-renewal loop).
      renew().catch(() => {})
    }, delay)
    // A background refresh must not keep a Node process alive (SSR / tests).
    ;(renewTimer as unknown as { unref?: () => void }).unref?.()
  }

  /** The current stored session (does not verify the signature — use verify() for that). */
  function getSession(): OrkestiaSession | null {
    const raw = store.getItem(K_SESSION)
    if (!raw) return null
    try {
      const s = JSON.parse(raw) as OrkestiaSession
      if (s.claims?.exp && s.claims.exp * 1000 < Date.now()) {
        signOut()
        return null
      }
      return s
    } catch {
      return null
    }
  }

  function signOut(): void {
    clearRenewTimer()
    store.removeItem(K_SESSION)
  }

  /**
   * Silently renew the access token via a hidden OIDC `prompt=none` authorization
   * against the hosted login. The identity tenant's session cookie
   * (login.orkestia.dev) carries the long-lived state, so a still-valid session
   * yields a fresh, short-lived access token with no UI and no full re-login.
   *
   * Rejects with {@link OrkestiaLoginRequiredError} when the session was revoked
   * or expired (`prompt=none` returns `login_required` / `interaction_required`),
   * having first cleared the local session and invoked `onRequiresLogin`. It does
   * not retry — the caller must run `signIn()`. Concurrent calls share one round trip.
   */
  async function renew(): Promise<OrkestiaSession> {
    if (renewInFlight) return renewInFlight
    renewInFlight = doRenew().finally(() => {
      renewInFlight = null
    })
    return renewInFlight
  }

  async function doRenew(): Promise<OrkestiaSession> {
    if (typeof document === 'undefined') {
      // No DOM (SSR / worker): a hidden iframe can't run here.
      // TODO: fall back to the narrow `identity.end-user.session.refresh` grant
      // once it ships (see gate1 plan) for non-browser / mobile-WebView renewal.
      throw new OrkestiaLoginRequiredError('no_dom', 'silent renewal requires a browser DOM')
    }
    const verifier = randomVerifier()
    const challenge = await challengeFor(verifier)
    const state = b64url(crypto.getRandomValues(new Uint8Array(16)).buffer)
    const q = new URLSearchParams({
      client_key: config.clientKey,
      redirect_uri: silentRedirectUri,
      state,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      prompt: 'none', // hidden renewal: the identity session cookie authorizes, no UI
    })

    let outcome: { code?: string; error?: string }
    try {
      outcome = await runHiddenAuthorize(`${loginUrl}/authorize?${q.toString()}`, state)
    } catch (err) {
      throw failRenew(err instanceof OrkestiaLoginRequiredError ? err : new OrkestiaLoginRequiredError('timeout'))
    }
    if (outcome.error || !outcome.code) {
      throw failRenew(new OrkestiaLoginRequiredError(outcome.error || 'login_required'))
    }

    const res = await fetch(`${api}/api/auth/end-user/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: outcome.code, code_verifier: verifier }),
    })
    const data = (await res.json().catch(() => ({}))) as { token?: string; message?: string; error?: string }
    if (!res.ok || !data.token) {
      throw failRenew(new OrkestiaLoginRequiredError('token_exchange_failed', data.message || data.error))
    }
    // Fresh token → fresh session (re-decodes claims so a changed role/capability
    // snapshot from whoami-on-renewal takes effect) and re-arms the next renewal.
    return setSession(data.token)
  }

  /** Common failure path: drop the session, stop the loop, signal the app, surface the error. */
  function failRenew(err: OrkestiaLoginRequiredError): OrkestiaLoginRequiredError {
    signOut() // clears the timer too — no reschedule, no loop
    config.onRequiresLogin?.(err)
    return err
  }

  /**
   * Drive a hidden iframe through `{loginUrl}/authorize?...&prompt=none` and read
   * the one-time `?code` (or `?error`) once it redirects back to our same-origin
   * `silentRedirectUri`. While the iframe sits on the login origin, reading its
   * location throws (cross-origin) — we swallow that and wait for the redirect.
   *
   * TODO: for a cross-origin `silentRedirectUri` (mobile WebView, 3rd-party-cookie
   * constraints) add a `postMessage`-based handshake from a dedicated silent page.
   */
  function runHiddenAuthorize(url: string, expectedState: string): Promise<{ code?: string; error?: string }> {
    return new Promise((resolve, reject) => {
      const iframe = document.createElement('iframe')
      iframe.style.display = 'none'
      iframe.setAttribute('aria-hidden', 'true')
      let settled = false

      const finish = (fn: () => void): void => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        iframe.removeEventListener('load', onLoad)
        try {
          iframe.parentNode?.removeChild(iframe)
        } catch {
          /* already detached */
        }
        fn()
      }

      const onLoad = (): void => {
        let href: string | undefined
        try {
          href = iframe.contentWindow?.location?.href
        } catch {
          return // still on the login origin (cross-origin) — await the redirect back
        }
        if (!href) return
        let parsed: URL
        try {
          parsed = new URL(href)
        } catch {
          return
        }
        const p = parsed.searchParams
        const code = p.get('code') ?? undefined
        const error = p.get('error') ?? undefined
        if (!code && !error) return // back on our origin but not the final redirect yet
        if (p.get('state') && p.get('state') !== expectedState) {
          finish(() => reject(new OrkestiaLoginRequiredError('state_mismatch')))
          return
        }
        finish(() => resolve({ code, error }))
      }

      const timer = setTimeout(
        () => finish(() => reject(new OrkestiaLoginRequiredError('timeout'))),
        silentTimeoutMs,
      )
      iframe.addEventListener('load', onLoad)
      iframe.src = url
      document.body.appendChild(iframe)
    })
  }

  /**
   * Verify a token's RS256 signature locally against the published JWKS. Returns
   * the claims on success, throws otherwise. Use server-side or for hardened clients.
   */
  async function verify(token: string): Promise<OrkestiaClaims> {
    const [h, p, sig] = token.split('.')
    const header = JSON.parse(new TextDecoder().decode(fromB64url(h))) as { kid?: string; alg?: string }
    const jwks = (await (await fetch(`${api}/api/auth/end-user/jwks`)).json()) as { keys: JsonWebKey[] }
    const jwk = jwks.keys.find((k) => (k as { kid?: string }).kid === header.kid) ?? jwks.keys[0]
    if (!jwk) throw new Error('no matching JWKS key')
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])
    const ok = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      key,
      fromB64url(sig),
      new TextEncoder().encode(`${h}.${p}`),
    )
    if (!ok) throw new Error('invalid token signature')
    const claims = decodeJwt(token)
    if (!claims) throw new Error('malformed token')
    if (claims.exp && claims.exp * 1000 < Date.now()) throw new Error('token expired')
    return claims
  }

  /** Create an end-user account (does not consume a seat; first login does). */
  async function register(email: string, password: string): Promise<void> {
    const res = await fetch(`${api}/api/auth/end-user/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_key: config.clientKey, email, password }),
    })
    if (!res.ok) {
      const e = (await res.json().catch(() => ({}))) as { message?: string }
      throw new Error(e.message || `register failed (${res.status})`)
    }
  }

  // Resume background renewal for a session already in storage on load.
  if (autoRenew) {
    const existing = getSession()
    if (existing) scheduleRenew(existing.claims)
  }

  // Account-portal launch: login.orkestia.dev/account appends ?orkestia_signin=1
  // so an unauthenticated app boot starts PKCE instead of showing its own form.
  if (typeof location !== 'undefined' && typeof location.search === 'string') {
    const boot = new URLSearchParams(location.search)
    if (boot.get('orkestia_signin') === '1' && !boot.get('code') && !getSession()) {
      void signIn()
    }
  }

  return { signIn, handleCallback, getSession, signOut, verify, register, renew }
}

export type OrkestiaAuth = ReturnType<typeof createOrkestiaAuth>
