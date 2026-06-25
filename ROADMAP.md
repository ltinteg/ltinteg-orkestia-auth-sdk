# Roadmap

The SDK works today: PKCE sign-in, one-time-code token exchange, local JWKS
verification, register. What's next to make **Sign in with Orkestia** fully
self-serve and production-grade.

## Auth platform (server side)
- [ ] **Refresh tokens** — silent session renewal past the access-token TTL (today the session ends at expiry and the user re-authenticates).
- [ ] **Discovery** — publish `/.well-known/openid-configuration` so standard OIDC tooling (and AI agents) can wire from a single URL.
- [ ] **Provisioning bundle** — provisioning returns the full client config (issuer + authorize/token/jwks URLs) alongside the `client_key`, so an integration can be wired without reading docs.
- [x] **Automatic origin allow-listing** — the `/authorize` and `/token` endpoints accept any of a client's registered redirect-URI origins automatically (no env change to onboard a new app).

## SDK
- [ ] **Framework adapters** — `useOrkestiaAuth()` React hook, Next.js route helpers, TanStack Start.
- [ ] **Build + types** — shipped `dist/` + `.d.ts` (tsup).
- [ ] **Tests + CI**.
- [ ] **npm publish** — deferred. For now, install from this repo.

## Docs
- [ ] Per-framework quickstarts and a hosted integration guide.
