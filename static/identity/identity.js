(() => {
  "use strict";

  // Only an opaque, server-created flow enters the page. Credentials and
  // interaction proofs live in memory; no OAuth parameters are reconstructed.
  const uuid7 = "[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
  const flowPattern = new RegExp(`^${uuid7}$`);
  const restartPattern = new RegExp(`^/sso/login\\?flow=${uuid7}$`);
  const csrfPattern = /^[0-9a-f]{64}$/;
  const purposes = Object.freeze({
    PLATFORM_CONSOLE: "员工控制台",
    CUSTOMER_PORTAL: "客户门户",
    ACCOUNT: "账号认证",
  });
  const scopeCopy = Object.freeze({
    openid: ["确认您的账号", "提供用于识别您账号的唯一标识。"],
    profile: ["基本账号资料", "提供您的用户名、姓名和头像（如已设置）。"],
    offline_access: ["保持此应用登录", "允许此应用保持登录，直至您的全局登录状态到期。"],
  });
  const byId = (id) => document.getElementById(id);
  const ui = {
    content: byId("auth-content"),
    title: byId("page-title"),
    description: byId("page-description"),
    client: byId("request-context"),
    clientName: byId("client-name"),
    clientPurpose: byId("client-purpose"),
    notice: byId("notice"),
    status: byId("screenreader-status"),
    error: byId("error-message"),
    loading: byId("loading-state"),
    login: byId("login-form"),
    username: byId("username"),
    usernameError: byId("username-error"),
    password: byId("password"),
    passwordError: byId("password-error"),
    toggle: byId("toggle-password"),
    loginSubmit: byId("login-submit"),
    consent: byId("consent-panel"),
    consentForm: byId("consent-form"),
    accountName: byId("account-name"),
    accountIdentifier: byId("account-identifier"),
    scopeList: byId("scope-list"),
    allow: byId("consent-allow"),
    deny: byId("consent-deny"),
    changeAccount: byId("change-account"),
    complete: byId("complete-panel"),
    completeMessage: byId("complete-message"),
    restart: byId("restart-panel"),
    restartButton: byId("restart-button"),
    recovery: byId("recovery-actions"),
    retry: byId("retry-button"),
  };
  let flow = null;
  let interaction = null;
  let busy = false;
  let pageActive = true;
  let pageGeneration = 0;
  const pendingRequests = new Set();

  class InactivePage extends Error {}

  class RequestFailure extends Error {
    constructor(status, retryAfter = null) {
      super("Authentication request did not complete");
      this.status = status;
      this.retryAfter = retryAfter;
    }
  }

  const nonemptyText = (value, limit) => typeof value === "string"
    && value.trim().length > 0 && value.length <= limit;

  async function request(path, { method = "GET", body, csrf } = {}) {
    if (!pageActive) throw new InactivePage();
    const generation = pageGeneration;
    const controller = new AbortController();
    pendingRequests.add(controller);
    const timer = window.setTimeout(() => controller.abort(), 15000);
    try {
      const headers = { Accept: "application/json" };
      if (body !== undefined) headers["Content-Type"] = "application/json";
      if (csrf !== undefined) headers["X-CSRF-Token"] = csrf;
      const response = await fetch(path, {
        method,
        headers,
        credentials: "same-origin",
        cache: "no-store",
        redirect: "error",
        signal: controller.signal,
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      if (!pageActive || generation !== pageGeneration) throw new InactivePage();
      if (!response.ok) {
        const rawRetry = response.headers.get("Retry-After");
        const retry = rawRetry && /^[0-9]{1,4}$/.test(rawRetry) ? Number(rawRetry) : null;
        throw new RequestFailure(response.status, retry && retry <= 3600 ? retry : null);
      }
      try {
        const value = await response.json();
        if (!pageActive || generation !== pageGeneration) throw new InactivePage();
        return value;
      } catch {
        if (!pageActive || generation !== pageGeneration) throw new InactivePage();
        throw new RequestFailure(502);
      }
    } catch (error) {
      if (!pageActive || generation !== pageGeneration || error instanceof InactivePage) throw new InactivePage();
      if (error instanceof RequestFailure) throw error;
      throw new RequestFailure(0);
    } finally {
      window.clearTimeout(timer);
      pendingRequests.delete(controller);
    }
  }

  function setBusy(value, action = "load") {
    busy = value;
    ui.content.setAttribute("aria-busy", String(value));
    ui.login.setAttribute("aria-busy", String(value && action === "login"));
    ui.consentForm.setAttribute("aria-busy", String(value && action !== "login"));
    for (const element of [ui.username, ui.password, ui.toggle, ui.loginSubmit,
      ui.allow, ui.deny, ui.changeAccount, ui.restartButton, ui.retry]) {
      element.disabled = value;
    }
    ui.loginSubmit.firstElementChild.textContent = value && action === "login" ? "正在验证…" : "登录并继续";
    ui.allow.firstElementChild.textContent = value && action === "approve" ? "正在确认…" : "同意并继续";
    ui.deny.textContent = value && action === "deny" ? "正在取消…" : "取消访问";
    ui.restartButton.textContent = value && action === "restart" ? "正在准备…" : "重新开始登录";
  }

  function clearMessages() {
    ui.error.hidden = true;
    ui.error.textContent = "";
    ui.notice.hidden = true;
    ui.notice.textContent = "";
    ui.status.textContent = "";
    ui.recovery.hidden = true;
  }

  function clearPassword() {
    ui.password.value = "";
    ui.password.type = "password";
    ui.toggle.textContent = "显示";
    ui.toggle.setAttribute("aria-label", "显示密码");
    ui.toggle.setAttribute("aria-pressed", "false");
  }

  function hidePanels() {
    for (const panel of [ui.loading, ui.login, ui.consent, ui.complete, ui.restart]) panel.hidden = true;
  }

  function announce(message) {
    ui.notice.textContent = message;
    ui.notice.hidden = false;
    ui.status.textContent = message;
  }

  function showError(message, { recover = false, focus = true } = {}) {
    ui.status.textContent = "";
    ui.notice.hidden = true;
    ui.error.textContent = message;
    ui.error.hidden = false;
    ui.recovery.hidden = !recover;
    if (focus) ui.error.focus();
  }

  function terminal(message) {
    interaction = null;
    clearPassword();
    hidePanels();
    clearMessages();
    ui.title.textContent = "暂时无法继续";
    ui.description.textContent = "请返回您要访问的应用，重新发起登录。";
    showError(message);
  }

  function publicError(error, context) {
    if (error.status === 429) {
      return error.retryAfter
        ? `操作较频繁，请在 ${error.retryAfter} 秒后重试。`
        : "操作较频繁，请稍候再试。";
    }
    if (error.status === 0 || error.status >= 500) return "认证服务暂时无法连接，请稍后重试。";
    if (context === "login" && error.status === 401) return "账号或密码不正确，请重新输入。";
    if (context === "login") return "本次登录未能完成，请再次尝试。若仍无法继续，请从应用重新发起登录。";
    return "本次访问请求已失效或无法确认，请从应用重新发起登录。";
  }

  function validateInteraction(value) {
    if (!value || typeof value !== "object" || !["LOGIN_REQUIRED", "CONSENT_REQUIRED", "RESTART_REQUIRED"].includes(value.status)
      || !value.client || !nonemptyText(value.client.name, 256)
      || !Object.hasOwn(purposes, value.client.purpose)
      || !Array.isArray(value.scopes) || value.scopes.length < 1 || value.scopes.length > 3
      || !value.scopes.includes("openid") || new Set(value.scopes).size !== value.scopes.length
      || !value.scopes.every((scope) => typeof scope === "string" && Object.hasOwn(scopeCopy, scope))
      || typeof value.csrfToken !== "string" || !csrfPattern.test(value.csrfToken)
      || typeof value.expiresAt !== "string" || !Number.isFinite(Date.parse(value.expiresAt))) {
      throw new RequestFailure(502);
    }
    if (value.status === "CONSENT_REQUIRED") {
      const account = value.account;
      if (!account || typeof account.id !== "string" || !flowPattern.test(account.id)
        || !nonemptyText(account.username, 256)
        || typeof account.realName !== "string" || account.realName.length > 256) {
        throw new RequestFailure(502);
      }
    } else if (value.account !== null) {
      throw new RequestFailure(502);
    }
    return value;
  }

  function renderInteraction(value, focus) {
    interaction = value;
    clearMessages();
    hidePanels();
    ui.clientName.textContent = value.client.name;
    ui.clientPurpose.textContent = purposes[value.client.purpose];
    ui.clientPurpose.hidden = false;
    ui.client.hidden = false;
    if (value.status === "LOGIN_REQUIRED") {
      ui.title.textContent = "登录您的账号";
      ui.description.textContent = "使用您的账号继续。登录后，再由您确认应用访问。";
      ui.login.hidden = false;
      clearPassword();
    } else if (value.status === "CONSENT_REQUIRED") {
      ui.title.textContent = "确认应用访问";
      ui.description.textContent = "请确认当前账号，并查看此应用申请获取的信息。";
      const displayName = value.account.realName.trim() || value.account.username;
      ui.accountName.textContent = displayName;
      ui.accountIdentifier.textContent = value.account.username;
      ui.accountIdentifier.hidden = displayName === value.account.username;
      ui.scopeList.replaceChildren();
      for (const scope of value.scopes) {
        const item = document.createElement("li");
        const title = document.createElement("span");
        const description = document.createElement("span");
        title.className = "scope-title";
        description.className = "scope-description";
        title.textContent = scopeCopy[scope][0];
        description.textContent = scopeCopy[scope][1];
        item.append(title, description);
        ui.scopeList.append(item);
      }
      ui.changeAccount.hidden = false;
      ui.consent.hidden = false;
    } else {
      ui.title.textContent = "请重新确认账号";
      ui.description.textContent = "为确保使用的是您选择的账号，请重新开始登录。";
      ui.restart.hidden = false;
    }
    if (focus) ui.title.focus();
  }

  async function loadInteraction(focus = false) {
    const value = await request(`/oidc/interaction/${flow}`);
    renderInteraction(validateInteraction(value), focus);
  }

  async function refresh(focus = false) {
    if (busy || !flow) return;
    clearMessages();
    setBusy(true);
    try {
      await loadInteraction(focus);
    } catch (error) {
      if (error instanceof InactivePage) return;
      interaction = null;
      if (error.status === 0 || error.status === 429 || error.status >= 500) {
        hidePanels();
        ui.title.textContent = "暂时无法连接";
        ui.description.textContent = "您的访问请求尚未确认，请稍后重新检查。";
        showError(publicError(error, "interaction"), { recover: true });
      } else {
        terminal(publicError(error, "interaction"));
      }
    } finally {
      if (pageActive) setBusy(false);
    }
  }

  function resetFieldErrors() {
    for (const [input, error] of [[ui.username, ui.usernameError], [ui.password, ui.passwordError]]) {
      input.removeAttribute("aria-invalid");
      error.textContent = "";
      error.hidden = true;
    }
  }

  function validateLogin() {
    resetFieldErrors();
    let firstInvalid = null;
    for (const [input, error, message] of [
      [ui.username, ui.usernameError, "请输入您的账号。"],
      [ui.password, ui.passwordError, "请输入密码。"],
    ]) {
      if (input === ui.username ? !input.value.trim() : !input.value) {
        input.setAttribute("aria-invalid", "true");
        error.textContent = message;
        error.hidden = false;
        firstInvalid ||= input;
      }
    }
    if (firstInvalid) firstInvalid.focus();
    return !firstInvalid;
  }

  ui.login.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (busy || interaction?.status !== "LOGIN_REQUIRED") return;
    clearMessages();
    if (!validateLogin()) return;
    setBusy(true, "login");
    announce("正在验证账号，请稍候。");
    let authenticated = false;
    try {
      // A fresh challenge is required for every attempt, including after an
      // incorrect password. The response never enters a hidden form or URL.
      const preauth = await request("/api/sso/preauth");
      if (!preauth || typeof preauth.csrfToken !== "string" || !csrfPattern.test(preauth.csrfToken)) {
        throw new RequestFailure(502);
      }
      await request("/api/sso/login", {
        method: "POST",
        csrf: preauth.csrfToken,
        body: { username: ui.username.value.trim(), password: ui.password.value },
      });
      authenticated = true;
      clearPassword();
      hidePanels();
      ui.loading.hidden = false;
      await loadInteraction(true);
    } catch (error) {
      if (error instanceof InactivePage) return;
      ui.notice.hidden = true;
      clearPassword();
      if (authenticated) {
        interaction = null;
        hidePanels();
        if (error.status === 0 || error.status === 429 || error.status >= 500) {
          ui.title.textContent = "登录成功，请重新检查请求";
          ui.description.textContent = "暂时无法载入应用的访问请求，请稍后重新检查。";
          showError(publicError(error, "interaction"), { recover: true });
        } else {
          terminal(publicError(error, "interaction"));
        }
      } else {
        showError(publicError(error, "login"));
      }
    } finally {
      if (pageActive) setBusy(false);
    }
  });

  function navigate(target, action) {
    if (!pageActive) throw new InactivePage();
    if (typeof target !== "string" || target.length > 8192 || /[\u0000-\u0020\u007f\\]/.test(target)) {
      throw new RequestFailure(502);
    }
    if (action === "restart") {
      if (!restartPattern.test(target)) throw new RequestFailure(502);
    } else {
      let destination;
      try { destination = new URL(target); } catch { throw new RequestFailure(502); }
      if (!target.startsWith("https://") || destination.protocol !== "https:"
        || destination.username || destination.password || destination.hash) {
        throw new RequestFailure(502);
      }
    }
    // The backend alone constructs the registered callback. This page never
    // accepts a return URL, redirect URI, state or code from its own URL.
    window.location.assign(target);
  }

  async function submitDecision(action) {
    if (busy || !interaction || !flow) return;
    if (action !== "restart" && interaction.status !== "CONSENT_REQUIRED") return;
    if (action === "restart" && !["CONSENT_REQUIRED", "RESTART_REQUIRED"].includes(interaction.status)) return;
    clearMessages();
    setBusy(true, action);
    announce(action === "restart" ? "正在准备新的登录页面。" : "正在处理您的选择，请稍候。");
    try {
      const result = await request(`/oidc/interaction/${flow}`, {
        method: "POST", csrf: interaction.csrfToken, body: { action },
      });
      hidePanels();
      ui.notice.hidden = true;
      ui.title.textContent = action === "deny" ? "已取消本次访问" : "即将继续";
      ui.description.textContent = action === "restart" ? "正在打开新的登录页面。" : "正在返回您刚才访问的应用。";
      ui.completeMessage.textContent = "请稍候，页面即将跳转。";
      ui.complete.hidden = false;
      ui.status.textContent = ui.description.textContent;
      navigate(result?.redirectTo, action);
    } catch (error) {
      if (error instanceof InactivePage) return;
      interaction = null;
      ui.notice.hidden = true;
      hidePanels();
      if (error.status === 0 || error.status === 429 || error.status >= 500) {
        ui.title.textContent = "请重新检查本次请求";
        ui.description.textContent = "暂时无法确认操作结果。重新检查后，再继续操作。";
        showError(publicError(error, "interaction"), { recover: true });
      } else {
        terminal(publicError(error, "interaction"));
      }
    } finally {
      if (pageActive) setBusy(false);
    }
  }

  ui.consentForm.addEventListener("submit", (event) => {
    event.preventDefault();
    void submitDecision("approve");
  });
  ui.deny.addEventListener("click", () => { void submitDecision("deny"); });
  ui.changeAccount.addEventListener("click", () => { void submitDecision("restart"); });
  ui.restartButton.addEventListener("click", () => { void submitDecision("restart"); });
  ui.retry.addEventListener("click", () => { void refresh(true); });
  ui.toggle.addEventListener("click", () => {
    const reveal = ui.password.type === "password";
    ui.password.type = reveal ? "text" : "password";
    ui.toggle.textContent = reveal ? "隐藏" : "显示";
    ui.toggle.setAttribute("aria-label", reveal ? "隐藏密码" : "显示密码");
    ui.toggle.setAttribute("aria-pressed", String(reveal));
  });
  for (const [input, error] of [[ui.username, ui.usernameError], [ui.password, ui.passwordError]]) {
    input.addEventListener("input", () => {
      input.removeAttribute("aria-invalid");
      error.hidden = true;
      error.textContent = "";
    });
  }
  window.addEventListener("pagehide", () => {
    pageActive = false;
    pageGeneration += 1;
    for (const controller of pendingRequests) controller.abort();
    pendingRequests.clear();
    clearPassword();
    interaction = null;
  });
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) window.location.reload();
  });

  const parameters = new URLSearchParams(window.location.search);
  const flowValues = parameters.getAll("flow");
  if (!window.location.hash && parameters.size === 0) {
    hidePanels();
    ui.title.textContent = "从应用开始，安心连接";
    ui.description.textContent = "请从您要访问的应用发起登录。";
    ui.completeMessage.textContent = "应用会带您回到这里，完成账号登录和访问确认。";
    ui.complete.hidden = false;
    setBusy(false);
  } else if (window.location.hash || parameters.size !== 1 || flowValues.length !== 1 || !flowPattern.test(flowValues[0])) {
    terminal("登录链接无效。请从您要访问的应用重新发起登录。");
    setBusy(false);
  } else {
    [flow] = flowValues;
    void refresh(false);
  }
})();
