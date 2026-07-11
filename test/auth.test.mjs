// @orkestia/auth — browser PKCE/session behavior (node:test, built dist).
import test from "node:test";
import assert from "node:assert/strict";
import { createOrkestiaAuth, OrkestiaLoginRequiredError } from "../dist/index.js";

const K_VERIFIER = "orkestia.pkce.verifier";
const K_STATE = "orkestia.pkce.state";
const K_SESSION = "orkestia.session";

function createStorage(initial = {}) {
  const data = new Map(Object.entries(initial));
  return {
    get length() {
      return data.size;
    },
    clear() {
      data.clear();
    },
    getItem(key) {
      return data.has(key) ? data.get(key) : null;
    },
    key(index) {
      return Array.from(data.keys())[index] ?? null;
    },
    removeItem(key) {
      data.delete(key);
    },
    setItem(key, value) {
      data.set(key, String(value));
    },
  };
}

function encodeJwtPart(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function makeToken(claims) {
  return `${encodeJwtPart({ alg: "none", typ: "JWT" })}.${encodeJwtPart(claims)}.sig`;
}

// Fake DOM for the hidden prompt=none renewal iframe. Setting `.src` simulates
// the login server processing the authorization and redirecting back to the
// same-origin silentRedirectUri with a one-time ?code (or ?error), echoing the
// state — exactly what runHiddenAuthorize reads off the iframe's location.
function installIframeDom({ mode = "success", code = "renewed-code", error = "login_required" } = {}) {
  let document;
  const iframe = {
    style: {},
    parentNode: null,
    _src: "",
    _load: [],
    contentWindow: { location: { href: "" } },
    setAttribute() {},
    addEventListener(type, cb) {
      if (type === "load") this._load.push(cb);
    },
    removeEventListener(type, cb) {
      if (type === "load") this._load = this._load.filter((f) => f !== cb);
    },
    get src() {
      return this._src;
    },
    set src(value) {
      this._src = value;
      if (mode === "stuck") return; // never redirects back → runHiddenAuthorize times out
      queueMicrotask(() => {
        const authUrl = new URL(value);
        const state = authUrl.searchParams.get("state");
        const back = new URL(authUrl.searchParams.get("redirect_uri"));
        if (mode === "error") back.searchParams.set("error", error);
        else back.searchParams.set("code", code);
        back.searchParams.set("state", mode === "badstate" ? "not-the-state" : state);
        this.contentWindow.location.href = back.toString();
        for (const cb of [...this._load]) cb();
      });
    },
  };
  document = {
    body: {
      appendChild(node) {
        node.parentNode = document.body;
      },
      removeChild(node) {
        node.parentNode = null;
      },
    },
    createElement() {
      return iframe;
    },
  };
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: document,
    writable: true,
  });
  return { iframe, document };
}

function installBrowserGlobals({ search = "", pathname = "/callback" } = {}) {
  const locationValue = {
    href: `https://app.example${pathname}${search}`,
    origin: "https://app.example",
    pathname,
    search,
  };
  const historyValue = {
    replaced: null,
    replaceState(...args) {
      this.replaced = args;
      locationValue.search = "";
      locationValue.href = `https://app.example${locationValue.pathname}`;
    },
  };
  Object.defineProperty(globalThis, "location", {
    configurable: true,
    value: locationValue,
    writable: true,
  });
  Object.defineProperty(globalThis, "history", {
    configurable: true,
    value: historyValue,
    writable: true,
  });
  return { history: historyValue, location: locationValue };
}

test("signIn stores PKCE verifier/state and redirects to hosted authorize", async () => {
  const storage = createStorage();
  installBrowserGlobals({ pathname: "/start" });
  const auth = createOrkestiaAuth({
    clientKey: "orkestia_client",
    loginUrl: "https://login.example/",
    redirectUri: "https://app.example/callback",
    storage,
  });

  await auth.signIn();

  const verifier = storage.getItem(K_VERIFIER);
  const state = storage.getItem(K_STATE);
  assert.match(verifier, /^[A-Za-z0-9_-]+$/);
  assert.match(state, /^[A-Za-z0-9_-]+$/);

  const redirect = new URL(location.href);
  assert.equal(`${redirect.origin}${redirect.pathname}`, "https://login.example/authorize");
  assert.equal(redirect.searchParams.get("client_key"), "orkestia_client");
  assert.equal(redirect.searchParams.get("redirect_uri"), "https://app.example/callback");
  assert.equal(redirect.searchParams.get("state"), state);
  assert.equal(redirect.searchParams.get("code_challenge_method"), "S256");
  assert.match(redirect.searchParams.get("code_challenge"), /^[A-Za-z0-9_-]+$/);
  assert.notEqual(redirect.searchParams.get("code_challenge"), verifier);
});

test("handleCallback exchanges code for a session and clears transient PKCE state", async (t) => {
  const storage = createStorage({
    [K_VERIFIER]: "verifier-1",
    [K_STATE]: "state-1",
  });
  const { history } = installBrowserGlobals({ search: "?code=code-1&state=state-1" });
  const token = makeToken({
    email: "user@example.com",
    end_user_uuid: "end-user-1",
    exp: Math.floor(Date.now() / 1000) + 3600,
  });
  let request;
  t.mock.method(globalThis, "fetch", async (url, init) => {
    request = { init, url };
    return new Response(JSON.stringify({ token }), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  });

  const auth = createOrkestiaAuth({
    clientKey: "orkestia_client",
    identityApi: "https://api.example/",
    storage,
  });
  const session = await auth.handleCallback();

  assert.equal(request.url, "https://api.example/api/auth/end-user/token");
  assert.equal(request.init.method, "POST");
  assert.deepEqual(JSON.parse(request.init.body), {
    code: "code-1",
    code_verifier: "verifier-1",
  });
  assert.equal(storage.getItem(K_VERIFIER), null);
  assert.equal(storage.getItem(K_STATE), null);
  assert.deepEqual(history.replaced, [null, "", "/callback"]);
  assert.equal(session.token, token);
  assert.equal(session.email, "user@example.com");
  assert.equal(session.endUserUuid, "end-user-1");
  assert.equal(JSON.parse(storage.getItem(K_SESSION)).token, token);
});

test("getSession clears and returns null for expired stored sessions", () => {
  const token = makeToken({
    email: "expired@example.com",
    exp: Math.floor(Date.now() / 1000) - 60,
  });
  const storage = createStorage({
    [K_SESSION]: JSON.stringify({
      claims: { email: "expired@example.com", exp: Math.floor(Date.now() / 1000) - 60 },
      email: "expired@example.com",
      token,
    }),
  });
  const auth = createOrkestiaAuth({ clientKey: "orkestia_client", storage });

  assert.equal(auth.getSession(), null);
  assert.equal(storage.getItem(K_SESSION), null);
});

test("register surfaces API error messages", async (t) => {
  const storage = createStorage();
  installBrowserGlobals();
  let request;
  t.mock.method(globalThis, "fetch", async (url, init) => {
    request = { init, url };
    return new Response(JSON.stringify({ message: "email already exists" }), {
      headers: { "Content-Type": "application/json" },
      status: 409,
    });
  });
  const auth = createOrkestiaAuth({
    clientKey: "orkestia_client",
    identityApi: "https://api.example/",
    storage,
  });

  await assert.rejects(
    auth.register("user@example.com", "secret-password"),
    /email already exists/,
  );
  assert.equal(request.url, "https://api.example/api/auth/end-user/register");
  assert.deepEqual(JSON.parse(request.init.body), {
    client_key: "orkestia_client",
    email: "user@example.com",
    password: "secret-password",
  });
});

test("renew silently refreshes the access token via a hidden prompt=none authorization", async (t) => {
  const storage = createStorage();
  const { iframe } = installIframeDom({ mode: "success" });
  const freshToken = makeToken({
    email: "user@example.com",
    end_user_uuid: "end-user-1",
    exp: Math.floor(Date.now() / 1000) + 3600,
  });
  let tokenReq;
  t.mock.method(globalThis, "fetch", async (url, init) => {
    tokenReq = { init, url };
    return new Response(JSON.stringify({ token: freshToken }), {
      headers: { "Content-Type": "application/json" },
      status: 200,
    });
  });

  const auth = createOrkestiaAuth({
    clientKey: "orkestia_client",
    loginUrl: "https://login.example/",
    identityApi: "https://api.example/",
    redirectUri: "https://app.example/callback",
    silentRedirectUri: "https://app.example/silent",
    autoRenew: false,
    storage,
  });
  const session = await auth.renew();

  // The hidden authorization is a full PKCE round trip carrying prompt=none.
  const authUrl = new URL(iframe.src);
  assert.equal(`${authUrl.origin}${authUrl.pathname}`, "https://login.example/authorize");
  assert.equal(authUrl.searchParams.get("prompt"), "none");
  assert.equal(authUrl.searchParams.get("redirect_uri"), "https://app.example/silent");
  assert.equal(authUrl.searchParams.get("client_key"), "orkestia_client");
  assert.equal(authUrl.searchParams.get("code_challenge_method"), "S256");
  assert.match(authUrl.searchParams.get("code_challenge"), /^[A-Za-z0-9_-]+$/);

  // The returned code is exchanged for a fresh token with its matching verifier.
  assert.equal(tokenReq.url, "https://api.example/api/auth/end-user/token");
  const body = JSON.parse(tokenReq.init.body);
  assert.equal(body.code, "renewed-code");
  assert.match(body.code_verifier, /^[A-Za-z0-9_-]+$/);

  // Fresh session is returned and persisted.
  assert.equal(session.token, freshToken);
  assert.equal(session.endUserUuid, "end-user-1");
  assert.equal(JSON.parse(storage.getItem(K_SESSION)).token, freshToken);
});

test("renew on a revoked/expired session signals requires-login and does not loop", async (t) => {
  const storage = createStorage({
    [K_SESSION]: JSON.stringify({
      claims: { email: "u@example.com", exp: Math.floor(Date.now() / 1000) + 3600 },
      email: "u@example.com",
      token: "stale-token",
    }),
  });
  installIframeDom({ mode: "error", error: "login_required" });
  const fetchMock = t.mock.method(globalThis, "fetch", async () =>
    new Response("{}", { status: 200 }),
  );
  const requiresLogin = [];
  const auth = createOrkestiaAuth({
    clientKey: "orkestia_client",
    loginUrl: "https://login.example/",
    identityApi: "https://api.example/",
    redirectUri: "https://app.example/callback",
    autoRenew: false,
    onRequiresLogin: (err) => requiresLogin.push(err),
    storage,
  });

  await assert.rejects(auth.renew(), (err) => {
    assert.ok(err instanceof OrkestiaLoginRequiredError);
    assert.equal(err.reason, "login_required");
    return true;
  });

  // Session dropped, app notified exactly once, and no token exchange attempted.
  assert.equal(storage.getItem(K_SESSION), null);
  assert.equal(requiresLogin.length, 1);
  assert.ok(requiresLogin[0] instanceof OrkestiaLoginRequiredError);
  assert.equal(fetchMock.mock.callCount(), 0);
});

test("renew times out into a requires-login signal when the iframe never returns", async (t) => {
  const storage = createStorage();
  installIframeDom({ mode: "stuck" });
  t.mock.method(globalThis, "fetch", async () => new Response("{}", { status: 200 }));
  const auth = createOrkestiaAuth({
    clientKey: "orkestia_client",
    loginUrl: "https://login.example/",
    identityApi: "https://api.example/",
    redirectUri: "https://app.example/callback",
    autoRenew: false,
    silentTimeoutMs: 25,
    storage,
  });

  await assert.rejects(auth.renew(), (err) => {
    assert.ok(err instanceof OrkestiaLoginRequiredError);
    assert.equal(err.reason, "timeout");
    return true;
  });
});
