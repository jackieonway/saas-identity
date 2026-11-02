(() => {
  "use strict";
  const byId = (id) => document.getElementById(id);
  const ui = {
    loading: byId("loading"), panel: byId("security-panel"), login: byId("login-needed"),
    message: byId("message"), error: byId("error"), title: byId("factor-title"),
    description: byId("factor-description"), recoveryCount: byId("recovery-count"),
    start: byId("start-enrollment"), enrollment: byId("enrollment-panel"),
    secret: byId("secret"), uri: byId("otpauth-uri"), confirm: byId("confirm-form"),
    confirmCode: byId("confirm-code"), recovery: byId("recovery-panel"),
    recoveryCodes: byId("recovery-codes"), recoveryDone: byId("recovery-done"),
    disable: byId("disable-form"), disableCode: byId("disable-code"),
  };
  let csrf = null;
  let busy = false;

  function showMessage(target, value) {
    for (const node of [ui.message, ui.error]) { node.hidden = true; node.textContent = ""; }
    target.textContent = value;
    target.hidden = false;
  }

  async function request(path, { method = "GET", body, csrfToken } = {}) {
    const headers = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
    let response;
    try {
      response = await fetch(path, {
        method, headers, credentials: "same-origin", cache: "no-store", redirect: "error",
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
    } catch {
      const error = new Error("request failed"); error.status = 0; throw error;
    }
    if (!response.ok) {
      const error = new Error("request failed"); error.status = response.status; throw error;
    }
    if (response.status === 204) return null;
    return response.json();
  }

  async function status() {
    const session = await request("/api/sso/session");
    csrf = session?.csrfToken;
    if (typeof csrf !== "string" || !/^[0-9a-f]{64}$/.test(csrf)) throw new Error("invalid session");
    const value = await request("/api/sso/mfa/status");
    ui.loading.hidden = true;
    ui.panel.hidden = false;
    ui.title.textContent = value.enabled ? "身份验证器已启用" : "尚未启用";
    ui.description.textContent = value.enabled
      ? "登录时需要身份验证器验证码。每个恢复码只可以使用一次。"
      : "绑定身份验证器后，登录时需要额外输入验证码。";
    ui.recoveryCount.textContent = value.enabled
      ? `剩余一次性恢复码：${value.availableRecoveryCodes}`
      : "建议在私人、安全的位置保存恢复码。";
    ui.start.hidden = value.enabled;
    ui.disable.hidden = !value.enabled;
  }

  function actionError(error, fallback) {
    if (error.status === 401) {
      ui.panel.hidden = true; ui.login.hidden = false; ui.loading.hidden = true;
      return;
    }
    showMessage(ui.error, error.status === 0 || error.status >= 500
      ? "认证服务暂时无法连接，请稍后重试。"
      : fallback);
  }

  ui.start.addEventListener("click", async () => {
    if (busy) return;
    busy = true; ui.start.disabled = true;
    try {
      const result = await request("/api/sso/mfa/enrollment", { method: "POST", body: {}, csrfToken: csrf });
      if (typeof result?.secret !== "string" || typeof result?.otpauthUri !== "string") throw new Error("invalid response");
      ui.secret.textContent = result.secret;
      ui.uri.textContent = result.otpauthUri;
      ui.enrollment.hidden = false;
      ui.confirmCode.focus();
      showMessage(ui.message, "绑定密钥只在此页面展示。完成验证后，密钥不会再次显示。");
    } catch (error) {
      actionError(error, error.status === 403 ? "绑定需要最近 5 分钟内重新输入密码，请登录后立即重试。" : "无法开始绑定，请重新登录后重试。");
    } finally { busy = false; ui.start.disabled = false; }
  });

  ui.confirm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    busy = true;
    try {
      const result = await request("/api/sso/mfa/enrollment/confirm", {
        method: "POST", body: { code: ui.confirmCode.value.trim() }, csrfToken: csrf,
      });
      if (!Array.isArray(result?.recoveryCodes) || result.recoveryCodes.length !== 10) throw new Error("invalid response");
      ui.enrollment.hidden = true;
      ui.start.hidden = true;
      ui.disable.hidden = true;
      ui.title.textContent = "身份验证器已启用";
      ui.description.textContent = "保存下方恢复码后，关闭或刷新页面。恢复码不会再次显示。";
      ui.recoveryCodes.replaceChildren(...result.recoveryCodes.map((code) => {
        const item = document.createElement("li"); const value = document.createElement("code");
        value.textContent = code; item.append(value); return item;
      }));
      ui.recovery.hidden = false;
      ui.confirmCode.value = "";
      showMessage(ui.message, "绑定成功。恢复码仅展示这一次。");
    } catch (error) {
      actionError(error, "验证码无效或绑定已过期。请检查身份验证器时间后重试。");
    } finally { busy = false; }
  });

  ui.recoveryDone.addEventListener("click", async () => {
    ui.recovery.hidden = true;
    ui.recoveryCodes.replaceChildren();
    await status().catch((error) => actionError(error, "无法读取最新安全状态。"));
  });

  ui.disable.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy) return;
    busy = true;
    try {
      await request("/api/sso/mfa/disable", {
        method: "POST", body: { code: ui.disableCode.value.trim() }, csrfToken: csrf,
      });
      ui.disableCode.value = "";
      showMessage(ui.message, "身份验证器已停用。相关安全事件已记录。");
      await status();
    } catch (error) {
      actionError(error, "停用未完成。请使用当前 6 位 TOTP 验证码重试。");
    } finally { busy = false; }
  });

  status().catch((error) => {
    if (error.status === 401) {
      ui.loading.hidden = true; ui.login.hidden = false;
    } else {
      ui.loading.hidden = true;
      showMessage(ui.error, "无法读取安全状态，请稍后重新载入。" );
    }
  });
})();
