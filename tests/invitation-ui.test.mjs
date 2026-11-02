import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../static/identity/invitation.js", import.meta.url), "utf8");
const invitation = "019abcdef012-3456";
const invitationId = "019a1234-abcd-7890-8123-123456789abc";
const verificationId = "019a1234-abcd-7890-9123-123456789abc";
const uuid7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function harness({ search = "", hash = "", path = `/sso/invitations/${invitationId}`, fetch } = {}) {
  const ids = ["invitation-content", "invitation-form", "invitation-token", "verification-ref", "new-username", "new-password", "operation-id", "invitation-submit", "invitation-error", "invitation-complete"];
  const elements = Object.fromEntries(ids.map((id) => [id, {
    value: "", disabled: id === "invitation-submit", hidden: ["invitation-error", "invitation-complete"].includes(id),
    textContent: "", firstElementChild: { textContent: "创建账号" }, listeners: {},
    addEventListener(event, callback) { this.listeners[event] = callback; },
    setAttribute(name, value) { this[name] = value; },
    focus() { this.focused = true; },
  }]));
  const form = elements["invitation-form"];
  form.reportValidity = () => true;
  form.reset = () => {
    form.listeners.reset?.();
    for (const id of ["invitation-token", "verification-ref", "new-username", "new-password", "operation-id"]) elements[id].value = "";
  };
  const listeners = {};
  const calls = [];
  const window = {
    location: { pathname: path, search, hash },
    setTimeout, clearTimeout,
    addEventListener(event, callback) { listeners[event] = callback; },
  };
  vm.runInNewContext(source, {
    document: { getElementById: (id) => elements[id] }, window, crypto: webcrypto,
    Uint8Array, TextEncoder, AbortController,
    fetch: async (url, options) => {
      calls.push({ url, options });
      return fetch ? fetch(url, options) : { ok: true, json: async () => ({ operationId: JSON.parse(options.body).operationId, invitationId, status: "ACCOUNT_CREATED" }) };
    },
  });
  function fill() {
    elements["invitation-token"].value = "x".repeat(43);
    elements["verification-ref"].value = verificationId;
    elements["new-username"].value = "new-account";
    elements["new-password"].value = "fixture-password-only";
  }
  const submit = () => form.listeners.submit({ preventDefault() {} });
  return { elements, listeners, calls, fill, submit };
}

test("invitation form creates a UUIDv7 operation without loading authority", () => {
  const ui = harness();
  assert.match(ui.elements["operation-id"].value, uuid7);
  assert.equal(ui.elements["invitation-submit"].disabled, false);
  assert.equal(ui.calls.length, 0);
});

test("submission clears secrets before transport and only accepts the exact safe result", async () => {
  let complete;
  const ui = harness({ fetch: () => new Promise((resolve) => { complete = resolve; }) });
  ui.fill();
  const operation = ui.elements["operation-id"].value;
  const pending = ui.submit();
  assert.equal(ui.elements["invitation-token"].value, "");
  assert.equal(ui.elements["new-password"].value, "");
  assert.equal(ui.elements["invitation-submit"].disabled, true);
  const { url, options } = ui.calls[0];
  assert.equal(url, `/api/sso/invitations/${invitationId}/accept`);
  assert.equal(options.method, "POST");
  assert.equal(options.credentials, "omit");
  assert.equal(options.cache, "no-store");
  assert.equal(options.redirect, "error");
  assert.equal(options.referrerPolicy, "no-referrer");
  assert.deepEqual(JSON.parse(options.body), {
    operationId: operation, token: "x".repeat(43), username: "new-account",
    password: "fixture-password-only", verificationRef: verificationId,
  });
  complete({ ok: true, json: async () => ({ operationId: operation, invitationId, status: "ACCOUNT_CREATED" }) });
  await pending;
  assert.equal(ui.elements["invitation-form"].hidden, true);
  assert.equal(ui.elements["invitation-complete"].hidden, false);
  assert.equal(ui.elements["invitation-error"].hidden, true);
});

test("rejections never read or display response details and keep the original operation for manual retry", async () => {
  let read = false;
  const ui = harness({ fetch: async () => ({ ok: false, status: 409, json() { read = true; throw new Error("private detail"); } }) });
  ui.fill();
  const operation = ui.elements["operation-id"].value;
  await ui.submit();
  assert.equal(read, false);
  assert.equal(ui.elements["operation-id"].value, operation);
  assert.equal(ui.elements["invitation-token"].value, "");
  assert.equal(ui.elements["new-password"].value, "");
  assert.equal(ui.elements["invitation-error"].hidden, false);
  assert.equal(ui.elements["invitation-error"].textContent.includes("private detail"), false);
  ui.fill();
  await ui.submit();
  assert.equal(JSON.parse(ui.calls[1].options.body).operationId, operation);
});

test("unknown results keep the operation and never echo exception text", async () => {
  const ui = harness({ fetch: async () => { throw new Error("fixture-secret-never-display"); } });
  ui.fill();
  const operation = ui.elements["operation-id"].value;
  await ui.submit();
  assert.equal(ui.elements["operation-id"].value, operation);
  assert.equal(ui.elements["invitation-error"].textContent.includes("fixture-secret"), false);
  assert.equal(ui.elements["invitation-token"].value, "");
  assert.equal(ui.elements["new-password"].value, "");
});

test("query, fragment, noncanonical paths and invalid verification cannot submit", async () => {
  for (const options of [{ search: "?token=unused" }, { hash: "#unused" }, { path: `/sso/invitations/${invitation}` }, { path: `/sso/invitations/${invitationId.toUpperCase()}` }]) {
    const ui = harness(options);
    assert.equal(ui.elements["invitation-form"].hidden, true);
    ui.fill();
    await ui.submit();
    assert.equal(ui.calls.length, 0);
  }
  const ui = harness();
  ui.fill();
  ui.elements["verification-ref"].value = "unknown";
  await ui.submit();
  assert.equal(ui.calls.length, 0);
  assert.equal(ui.elements["invitation-token"].value, "");
  assert.equal(ui.elements["new-password"].value, "");
});

test("leaving clears fields and aborts transport; a late result cannot update the restored page", async () => {
  let complete;
  const ui = harness({ fetch: () => new Promise((resolve) => { complete = resolve; }) });
  ui.fill();
  const operation = ui.elements["operation-id"].value;
  const pending = ui.submit();
  ui.listeners.pagehide();
  assert.equal(ui.calls[0].options.signal.aborted, true);
  ui.listeners.pageshow({ persisted: true });
  complete({ ok: true, json: async () => ({ operationId: operation, invitationId, status: "ACCOUNT_CREATED" }) });
  await pending;
  assert.equal(ui.elements["invitation-complete"].hidden, true);
  assert.equal(ui.elements["invitation-form"].hidden, false);
  assert.equal(ui.elements["operation-id"].value, operation);
  assert.equal(ui.elements["invitation-token"].value, "");
  assert.equal(ui.elements["new-password"].value, "");
});
