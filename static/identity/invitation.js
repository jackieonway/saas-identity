(() => {
  "use strict";

  const uuid7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const match = /^\/sso\/invitations\/([^/]+)$/.exec(window.location.pathname);
  const byId = (id) => document.getElementById(id);
  const ui = {
    content: byId("invitation-content"), form: byId("invitation-form"),
    token: byId("invitation-token"), verification: byId("verification-ref"),
    username: byId("new-username"), password: byId("new-password"),
    operation: byId("operation-id"), submit: byId("invitation-submit"),
    error: byId("invitation-error"), complete: byId("invitation-complete"),
  };
  let busy = false;
  let active = true;
  let generation = 0;
  let pending = null;

  function clearSecrets() {
    ui.token.value = "";
    ui.password.value = "";
  }

  function showError(message) {
    ui.error.textContent = message;
    ui.error.hidden = false;
    ui.error.focus();
  }

  function setBusy(value) {
    busy = value;
    ui.content.setAttribute("aria-busy", String(value));
    for (const input of [ui.token, ui.verification, ui.username, ui.password, ui.operation, ui.submit]) input.disabled = value;
    ui.submit.firstElementChild.textContent = value ? "正在创建…" : "创建账号";
  }

  function newOperation() {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    let timestamp = BigInt(Date.now());
    for (let index = 5; index >= 0; index -= 1) {
      bytes[index] = Number(timestamp & 255n);
      timestamp >>= 8n;
    }
    bytes[6] = (bytes[6] & 15) | 112;
    bytes[8] = (bytes[8] & 63) | 128;
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  ui.form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy || !active || ui.submit.disabled) return;
    ui.error.hidden = true;
    if (!ui.form.reportValidity()) return;
    if (!uuid7.test(ui.operation.value) || !uuid7.test(ui.verification.value)) {
      clearSecrets();
      showError("请填写完整的小写 UUIDv7 核验编号和领取操作编号，然后重新输入邀请凭证与密码。");
      return;
    }
    if (ui.username.value.trim() !== ui.username.value || /[\u0000-\u001f\u007f-\u009f]/u.test(ui.username.value)) {
      clearSecrets();
      showError("用户名不能包含首尾空格或控制字符，请调整后重新输入邀请凭证与密码。");
      return;
    }
    const operation = ui.operation.value;
    let body = JSON.stringify({
      operationId: operation, token: ui.token.value, username: ui.username.value,
      password: ui.password.value, verificationRef: ui.verification.value,
    });
    clearSecrets();
    if (new TextEncoder().encode(body).length > 4096) {
      body = null;
      showError("填写内容过长，请缩短后重新输入邀请凭证与密码。");
      return;
    }
    setBusy(true);
    const requestGeneration = generation;
    const controller = new AbortController();
    pending = controller;
    const timer = window.setTimeout(() => controller.abort(), 15000);
    try {
      const response = await fetch(`/api/sso/invitations/${match[1]}/accept`, {
        method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json" },
        credentials: "omit", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer",
        signal: controller.signal, body,
      });
      body = null;
      if (!active || requestGeneration !== generation) return;
      if (!response.ok) {
        if (response.status === 429 || response.status >= 500) {
          showError("暂时无法确认领取结果。请保留原操作编号，稍后重新填写相同内容重试。");
        } else {
          showError("未完成领取。请核对邀请凭证、核验编号、用户名及密码规则；若之前结果未确认，请使用原操作编号和相同内容重试。");
        }
        return;
      }
      const result = await response.json();
      if (!active || requestGeneration !== generation) return;
      if (!result || Object.keys(result).sort().join(",") !== "invitationId,operationId,status"
        || result.operationId !== operation || result.invitationId !== match[1] || result.status !== "ACCOUNT_CREATED") {
        throw new Error("Unconfirmed invitation result");
      }
      ui.form.reset();
      clearSecrets();
      ui.form.hidden = true;
      ui.complete.hidden = false;
      ui.complete.focus();
    } catch {
      if (active && requestGeneration === generation) {
        showError("暂时无法确认领取结果。请保留原操作编号，稍后重新填写相同内容重试。");
      }
    } finally {
      body = null;
      clearSecrets();
      window.clearTimeout(timer);
      if (pending === controller) pending = null;
      if (active && requestGeneration === generation) setBusy(false);
    }
  });

  ui.form.addEventListener("reset", clearSecrets);
  window.addEventListener("pagehide", () => {
    active = false;
    generation += 1;
    pending?.abort();
    clearSecrets();
  });
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) {
      active = true;
      clearSecrets();
      setBusy(false);
    }
  });

  clearSecrets();
  if (!match || !uuid7.test(match[1]) || window.location.search || window.location.hash) {
    ui.form.hidden = true;
    showError("邀请链接格式无效，请使用收到的原始邀请链接。");
    return;
  }
  try {
    ui.operation.value = newOperation();
    ui.submit.disabled = false;
  } catch {
    ui.form.hidden = true;
    showError("当前浏览器无法安全生成操作编号，请使用支持安全连接的浏览器重新打开邀请链接。");
  }
})();
