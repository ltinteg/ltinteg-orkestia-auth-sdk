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
function fromB64url(s: string): Uint8Array {
  const pad = s.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(pad + '='.repeat((4 - (pad.length % 4)) % 4))
  return Uint8Array.from(bin, (c) => c.charCodeAt(0))
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
    return session
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
    store.removeItem(K_SESSION)
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

  return { signIn, handleCallback, getSession, signOut, verify, register }
}

export type OrkestiaAuth = ReturnType<typeof createOrkestiaAuth>
