# @orkestia/auth

**Sign in with Orkestia** — a tiny, framework-agnostic browser SDK for the [Orkestia](https://orkestia.dev) end-user identity flow. PKCE authorization-code, no secret in the browser, local JWT verification.

## Install

> Early access — not yet on npm. Install from this repo (it builds on install):
>
> ```bash
> npm i github:ltinteg/ltinteg-orkestia-auth-sdk
> ```
>
> `npm i @orkestia/auth` will work once published. See the [roadmap](./ROADMAP.md).

## Quickstart

```ts
import { createOrkestiaAuth } from '@orkestia/auth'

const auth = createOrkestiaAuth({ clientKey: 'orkestia_…' }) // from identity.app.provision

// 1. On your "Sign in" button:
await auth.signIn()

// 2. On your redirect_uri page (must be registered for the client):
const session = await auth.handleCallback() // { token, claims, email, endUserUuid } | null

// 3. Anywhere:
const current = auth.getSession()
auth.signOut()
```

That's the whole integration. `signIn()` builds a PKCE challenge and redirects to the hosted login (`login.orkestia.dev`); after the user authenticates, Orkestia returns to your `redirect_uri` with a one-time `?code`, and `handleCallback()` exchanges it for an **RS256 JWT** at the identity API. The token never appears in a URL.

## API

| Method | Purpose |
|---|---|
| `signIn()` | Begin PKCE: redirect to the hosted login |
| `handleCallback()` | Exchange the `?code` for a token; returns `OrkestiaSession \| null` |
| `getSession()` | Current stored session (claims decoded; expiry checked) |
| `signOut()` | Clear the local session |
| `verify(token)` | Verify the RS256 signature against the published JWKS (returns claims) |
| `register(email, password)` | Create an end-user account (does not consume a seat) |

## Config

```ts
createOrkestiaAuth({
  clientKey: 'orkestia_…',                       // required
  loginUrl: 'https://login.orkestia.dev',        // default
  identityApi: 'https://workflow-api.orkestia.dev', // default
  redirectUri: location.origin + '/',            // default; must be registered
  storage: sessionStorage,                       // default
})
```

## The contract it implements

- Authorize (redirect): `GET {loginUrl}/authorize?client_key&redirect_uri&state&code_challenge&code_challenge_method=S256`
- Token exchange: `POST {identityApi}/api/auth/end-user/token` `{ code, code_verifier }` → `{ token }`
- Verification: `GET {identityApi}/api/auth/end-user/jwks` (RS256, `iss=login.orkestia.dev`)
- Register / verify-email / password-reset / mfa: under `{identityApi}/api/auth/end-user/*`

## Status

`v0.0.x` — early access. The API may change before `1.0`.
