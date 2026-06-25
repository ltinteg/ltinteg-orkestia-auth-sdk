# Roadmap

The SDK works today: PKCE sign-in, one-time-code token exchange, local JWKS
verification, register. What's next to make **Sign in with Orkestia** fully
self-serve and production-grade.

## Auth platform (server side)
- [ ] **Refresh tokens** — silent session renewal past the access-token TTL (today the session ends at expiry and the user re-authenticates).
- [x] **Discovery** — `https://login.orkestia.dev/.well-known/openid-configuration` publishes the authorize/token/jwks endpoints, PKCE method, and signing alg. One fetch → the contract.
- [x] **Provisioning bundle (one-call setup)** — `identity.app.provision` accepts `redirect_uris` and returns `client_key` + `client_uuid` + the `integration` bundle (issuer/authorize/token/jwks URLs). An MCP agent wires an app in a single call, no docs, no human.
- [x] **Automatic origin allow-listing** — the `/authorize` and `/token` endpoints accept any of a client's registered redirect-URI origins automatically (no env change to onboard a new app).

## SDK
- [ ] **Framework adapters** — `useOrkestiaAuth()` React hook, Next.js route helpers, TanStack Start.
- [ ] **Build + types** — shipped `dist/` + `.d.ts` (tsup).
- [ ] **Tests + CI**.
- [ ] **npm publish** — deferred. For now, install from this repo.

## Docs
- [ ] Per-framework quickstarts and a hosted integration guide.
