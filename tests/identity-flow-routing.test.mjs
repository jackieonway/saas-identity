import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../static/identity/identity.js", import.meta.url), "utf8");
const flow = "019a1163-0000-7000-8000-000000000001";
const nextFlow = "019a1163-0000-7000-8000-000000000002";
const csrf = "a".repeat(64);

function element() {
  return {
    value: "", hidden: false, disabled: false, textContent: "", type: "password",
    children: [], dataset: {}, firstElementChild: { textContent: "" }, listeners: {},
    classList: { toggle() {} },
    addEventListener(name, callback) { this.listeners[name] = callback; },
    setAttribute(name, value) { this[name] = value; },
    removeAttribute(name) { delete this[name]; },
    querySelectorAll() { return []; },
    replaceChildren(...children) { this.children = children; },
    append(...children) { this.children.push(...children); },
    focus() {},
  };
}

function harness({ pathname = "/oauth/login", search = `?flow=${flow}`, status = "LOGIN_REQUIRED", target = `/oauth/login?flow=${nextFlow}` } = {}) {
  const elements = new Map();
  const calls = [];
  const navigations = [];
  const listeners = {};
  let authenticated = false;
  const view = () => ({
    status, client: { name: "Owned application", purpose: "PLATFORM_CONSOLE" },
    account: null, scopes: ["openid", "profile"], csrfToken: csrf,
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
  });
  vm.runInNewContext(source, {
    URL, URLSearchParams, AbortController,
    document: {
      getElementById(id) {
        if (!elements.has(id)) elements.set(id, element());
        return elements.get(id);
      },
      createElement: element,
    },
    window: {
      location: { pathname, search, hash: "", assign: (value) => navigations.push(value) },
      setTimeout, clearTimeout,
      addEventListener(name, callback) { listeners[name] = callback; },
    },
    fetch: async (url, options) => {
      calls.push({ url, options });
      let body;
      if (url === "/api/sso/preauth") body = { csrfToken: csrf };
      else if (url === "/api/sso/login") { authenticated = true; body = { authenticated: true }; }
      else if (options.method === "POST") body = { redirectTo: target };
      else body = view();
      return { ok: true, headers: { get: () => null }, json: async () => body };
    },
  });
  return { elements, calls, navigations, listeners, authenticated: () => authenticated };
}

async function settle() {
  await new Promise(setImmediate);
}

for (const pathname of ["/oauth/login", "/sso/login"]) {
  test(`${pathname} with a flow loads only the canonical interaction`, async () => {
    const ui = harness({ pathname });
    await settle();
    assert.deepEqual(ui.calls.map(({ url }) => url), [`/oauth/interaction/${flow}`]);
    assert.equal(ui.elements.get("login-form").hidden, false);
    assert.equal(ui.elements.get("error-message").hidden, true);
  });
}

test("restart accepts the server's canonical login path and posts the original flow", async () => {
  const ui = harness({ pathname: "/sso/login", status: "RESTART_REQUIRED" });
  await settle();
  ui.elements.get("restart-button").listeners.click();
  await settle();
  assert.deepEqual(ui.navigations, [`/oauth/login?flow=${nextFlow}`]);
  assert.deepEqual(ui.calls.map(({ url }) => url), [`/oauth/interaction/${flow}`, `/oauth/interaction/${flow}`]);
  const { options } = ui.calls[1];
  assert.equal(options.method, "POST");
  assert.equal(options.headers["X-CSRF-Token"], csrf);
  assert.deepEqual(JSON.parse(options.body), { action: "restart" });
});

test("restart rejects legacy, external and extended targets without navigating", async () => {
  for (const target of [
    `/sso/login?flow=${nextFlow}`,
    `https://other.example.test/oauth/login?flow=${nextFlow}`,
    `//other.example.test/oauth/login?flow=${nextFlow}`,
    `/oauth/login?flow=${nextFlow}&return=other`,
    `/oauth/login?flow=${nextFlow}#fragment`,
  ]) {
    const ui = harness({ status: "RESTART_REQUIRED", target });
    await settle();
    ui.elements.get("restart-button").listeners.click();
    await settle();
    assert.deepEqual(ui.navigations, [], target);
    assert.equal(ui.elements.get("error-message").hidden, false, target);
  }
});

test("SSO login without a flow performs no OAuth interaction", async () => {
  const ui = harness({ pathname: "/sso/login", search: "" });
  await settle();
  assert.deepEqual(ui.calls, []);
  assert.equal(ui.elements.get("complete-panel").hidden, false);
});

test("account authentication keeps the SSO API and reloads the canonical flow", async () => {
  const ui = harness({ pathname: "/sso/login" });
  await settle();
  ui.elements.get("username").value = "owned-account";
  ui.elements.get("password").value = "owned-password";
  ui.elements.get("mfa-field").hidden = true;
  await ui.elements.get("login-form").listeners.submit({ preventDefault() {} });
  await settle();
  assert.equal(ui.authenticated(), true);
  assert.deepEqual(ui.calls.map(({ url }) => url), [
    `/oauth/interaction/${flow}`, "/api/sso/preauth", "/api/sso/login", `/oauth/interaction/${flow}`,
  ]);
  assert.equal(ui.elements.get("password").value, "");
  assert.deepEqual(JSON.parse(ui.calls[2].options.body), { username: "owned-account", password: "owned-password" });
});
