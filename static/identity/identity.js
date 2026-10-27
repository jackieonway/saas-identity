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
    selection: byId("context-selection"),
    selectionTitle: byId("context-title"),
    tenant: byId("selection-tenant"),
    tenantChoices: byId("tenant-choices"),
    search: byId("selection-search"),
    members: byId("selection-members"),
    memberCount: byId("selection-count"),
    emptyMembers: byId("selection-empty"),
    selectionSummary: byId("selection-summary"),
    steps: byId("auth-steps"),
    permissions: byId("permissions"),
    tenantStep: byId("tenant-step"),
    organizationStep: byId("organization-step"),
    organizationChoices: byId("organization-choices"),
    selectedTenant: byId("selected-tenant"),
    selectionHint: byId("selection-hint"),
    back: byId("selection-back"),
  };
  let flow = null;
  let interaction = null;
  let busy = false;
  let selectedMembership = null;
  let selectionStage = "tenant";
  let tenantCount = 0;
  const automaticAttempts = new Set();
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
      ui.allow, ui.deny, ui.changeAccount, ui.restartButton, ui.retry, ui.tenant, ui.search, ui.back]) {
      element.disabled = value;
    }
    ui.loginSubmit.firstElementChild.textContent = value && action === "login" ? "正在验证…" : "登录并继续";
    ui.allow.firstElementChild.textContent = value && ["approve", "consent"].includes(action) ? "正在确认…" : interaction?.status === "CONTEXT_SELECTION_REQUIRED" ? selectionStage === "tenant" ? "下一步：选择组织" : "进入应用" : "同意并继续";
    ui.allow.hidden = interaction?.status === "CONTEXT_SELECTION_REQUIRED" && selectionStage === "tenant";
    for (const button of ui.tenantChoices.querySelectorAll("button")) button.disabled = value;
    ui.deny.textContent = value && action === "deny" ? "正在取消…" : "取消本次访问";
    ui.restartButton.textContent = value && action === "restart" ? "正在准备…" : "重新开始登录";
    selectionAvailability();
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
    if (!value || typeof value !== "object" || !["LOGIN_REQUIRED", "CONSENT_REQUIRED", "CONTEXT_SELECTION_REQUIRED", "RESTART_REQUIRED"].includes(value.status)
      || !value.client || !nonemptyText(value.client.name, 256)
      || !Object.hasOwn(purposes, value.client.purpose)
      || !Array.isArray(value.scopes) || value.scopes.length < 1 || value.scopes.length > 3
      || !value.scopes.includes("openid") || new Set(value.scopes).size !== value.scopes.length
      || !value.scopes.every((scope) => typeof scope === "string" && Object.hasOwn(scopeCopy, scope))
      || typeof value.csrfToken !== "string" || !csrfPattern.test(value.csrfToken)
      || typeof value.expiresAt !== "string" || !Number.isFinite(Date.parse(value.expiresAt))) {
      throw new RequestFailure(502);
    }
    if (["CONSENT_REQUIRED", "CONTEXT_SELECTION_REQUIRED"].includes(value.status)) {
      const account = value.account;
      if (!account || typeof account.id !== "string" || !flowPattern.test(account.id)
        || !nonemptyText(account.username, 256)
        || typeof account.realName !== "string" || account.realName.length > 256) {
        throw new RequestFailure(502);
      }
    } else if (value.account !== null) {
      throw new RequestFailure(502);
    }
    if (value.status === "CONTEXT_SELECTION_REQUIRED") {
      const selection = value.contextSelection;
      const expectedType = value.client.purpose === "PLATFORM_CONSOLE" ? "EMPLOYEE" : value.client.purpose === "CUSTOMER_PORTAL" ? "CUSTOMER" : null;
      if (!expectedType || !selection || !["LOGIN", "SWITCH"].includes(selection.mode)
        || !Array.isArray(selection.members) || selection.members.length > 256
        || typeof selection.expiresAt !== "string" || !Number.isFinite(Date.parse(selection.expiresAt))
        || Date.parse(selection.expiresAt) <= Date.now()) throw new RequestFailure(502);
      const ids = new Set();
      for (const member of selection.members) {
        if (!member || ![member.membershipId, member.userId, member.tenantId, member.organizationId].every((id) => typeof id === "string" && flowPattern.test(id))
          || member.userId !== value.account.id || member.memberType !== expectedType || ids.has(member.membershipId)
          || typeof member.identityVersion !== "string" || !/^[1-9][0-9]{0,18}$/.test(member.identityVersion)
          || BigInt(member.identityVersion) > 9223372036854775807n
          || !nonemptyText(member.tenantName, 400) || !nonemptyText(member.organizationName, 400)
          || typeof member.organizationPath !== "string" || member.organizationPath.length > 8192) throw new RequestFailure(502);
        ids.add(member.membershipId);
      }
    }
    return value;
  }

  function selectionAvailability() {
    if (interaction?.status !== "CONTEXT_SELECTION_REQUIRED") return;
    ui.allow.disabled = busy || Date.parse(interaction.contextSelection.expiresAt) <= Date.now()
      || (selectionStage === "tenant" ? !ui.tenant.value : !interaction.contextSelection.members.some((member) => member.membershipId === selectedMembership && member.tenantId === ui.tenant.value));
    for (const radio of ui.members.querySelectorAll("input")) radio.disabled = busy;
  }

  function renderMembers() {
    const members = interaction?.contextSelection?.members || [];
    const search = ui.search.value.trim().toLocaleLowerCase();
    const visible = members.filter((member) => member.tenantId === ui.tenant.value
      && `${member.organizationName} ${member.organizationPath}`.toLocaleLowerCase().includes(search));
    ui.members.replaceChildren();
    for (const member of visible) {
      const label = document.createElement("label"); label.className = "member-choice";
      const radio = document.createElement("input"); radio.type = "radio"; radio.name = "context-membership";
      radio.value = member.membershipId; radio.checked = selectedMembership === member.membershipId;
      radio.addEventListener("change", () => { selectedMembership = member.membershipId; renderSelectionSummary(); selectionAvailability(); });
      const copy = document.createElement("span"); copy.className = "member-choice-copy";
      const name = document.createElement("span"); name.className = "member-choice-name"; name.textContent = member.organizationName;
      const path = document.createElement("span"); path.className = "member-choice-path"; path.textContent = member.organizationPath || member.tenantName;
      const type = document.createElement("span"); type.className = "member-choice-type"; type.textContent = member.memberType === "EMPLOYEE" ? "员工身份" : "客户身份";
      copy.append(name, path, type); label.append(radio, copy); ui.members.append(label);
    }
    ui.memberCount.textContent = ui.tenant.value ? `${visible.length} 个组织身份` : `${new Set(members.map((m) => m.tenantId)).size} 个租户`;
    ui.emptyMembers.hidden = visible.length > 0;
    ui.emptyMembers.textContent = !members.length ? "当前账号没有可访问此应用的成员身份。您可以取消并返回应用。"
      : !ui.tenant.value ? "请先选择此次要进入的租户。" : "没有找到匹配的组织，请调整搜索条件。";
    renderSelectionSummary();
    selectionAvailability();
  }

  function renderSelectionSummary() {
    const selected = interaction?.contextSelection?.members.find((member) => member.membershipId === selectedMembership);
    ui.selectionSummary.textContent = selected ? `已选：${selected.tenantName} / ${selected.organizationName}` : "选择身份后继续，权限以该组织为准。";
  }

  function renderSelection(value) {
    selectionStage = "tenant";
    selectedMembership = null; ui.search.value = ""; ui.tenant.replaceChildren();
    const tenants = new Map(value.contextSelection.members.map((member) => [member.tenantId, member.tenantName]));
    tenantCount = tenants.size;
    ui.tenantChoices.replaceChildren();
    const placeholder = document.createElement("option"); placeholder.value = ""; placeholder.textContent = "请选择租户"; ui.tenant.append(placeholder);
    for (const [id, name] of tenants) {
      const option = document.createElement("option"); option.value = id; option.textContent = name; ui.tenant.append(option);
      const button = document.createElement("button"); button.type = "button"; button.className = "tenant-choice";
      const title = document.createElement("strong"); title.textContent = name;
      const detail = document.createElement("span"); detail.textContent = `${value.contextSelection.members.filter(m => m.tenantId === id).length} 个可用组织身份`;
      const arrow = document.createElement("span"); arrow.className = "choice-arrow"; arrow.textContent = "→"; arrow.setAttribute("aria-hidden", "true");
      button.append(title, detail, arrow);
      button.addEventListener("click", () => {
        if (busy) return;
        ui.tenant.value = id; selectedMembership = null; ui.search.value = "";
        selectionStage = "organization"; renderMembers(); showSelectionStage(true);
        void continueAutomatically();
      });
      ui.tenantChoices.append(button);
    }
    if (tenants.size === 1) {
      ui.tenant.value = tenants.keys().next().value;
      selectionStage = "organization";
    }
    if (value.contextSelection.members.length === 1) selectedMembership = value.contextSelection.members[0].membershipId;
    ui.selectionTitle.textContent = value.contextSelection.mode === "SWITCH" ? "切换组织与身份" : "选择此次使用的身份";
    renderMembers();
    showSelectionStage();
  }

  function showSteps(index) {
    ui.steps.hidden = true;
    Array.from(ui.steps.children).forEach((step, position) => {
      if (position === index) step.setAttribute("aria-current", "step"); else step.removeAttribute("aria-current");
      step.classList.toggle("step-complete", position < index);
    });
  }

  function showSelectionStage(focus = false) {
    const organization = selectionStage === "organization";
    ui.title.textContent = organization ? "选择组织" : "选择租户";
    ui.description.textContent = organization ? "选择此次使用的工作身份，继续进入应用。" : "选择一个租户，继续查看您可用的组织身份。";
    ui.selectionTitle.textContent = organization ? "此租户下的可用组织" : "您可以访问的租户";
    ui.selectionHint.textContent = organization ? "仅显示所选租户中，您可用于此应用的身份。" : "下一步将显示此租户下可用的组织。";
    ui.tenantStep.hidden = organization;
    ui.organizationStep.hidden = !organization;
    ui.organizationChoices.hidden = !organization;
    ui.selectionSummary.hidden = !organization;
    ui.memberCount.hidden = !organization;
    ui.emptyMembers.hidden = organization ? ui.members.childElementCount > 0 : interaction.contextSelection.members.length > 0;
    if (!organization && !interaction.contextSelection.members.length) ui.emptyMembers.textContent = "您目前没有可访问的租户和组织，请联系管理员。";
    ui.selectedTenant.textContent = ui.tenant.selectedOptions[0]?.textContent || "";
    ui.back.hidden = !organization || tenantCount <= 1;
    showSteps(organization ? 3 : 2);
    setBusy(busy);
    if (focus) ui.title.focus();
  }

  async function continueAutomatically() {
    if (busy || !pageActive || !interaction) return;
    if (interaction.status === "CONSENT_REQUIRED" && interaction.consentRemembered === true && !interaction.contextSelectionRequired) {
      const key = `${flow}:remembered`;
      if (automaticAttempts.has(key)) return;
      automaticAttempts.add(key); await submitDecision("approve"); return;
    }
    if (interaction.status !== "CONTEXT_SELECTION_REQUIRED" || selectionStage !== "organization") return;
    // Count the actual server-supplied choices, never the filtered search results.
    const members = interaction.contextSelection.members.filter(m => m.tenantId === ui.tenant.value);
    if (members.length !== 1) return;
    const key = `${flow}:${members[0].membershipId}`;
    if (automaticAttempts.has(key)) return;
    automaticAttempts.add(key); selectedMembership = members[0].membershipId;
    await submitDecision("approve");
  }

  function renderInteraction(value, focus) {
    interaction = value;
    ui.content.dataset.screen = value.status;
    clearMessages();
    hidePanels();
    ui.selection.hidden = true;
    ui.back.hidden = true;
    ui.permissions.hidden = value.status === "CONTEXT_SELECTION_REQUIRED";
    showSteps(value.status === "LOGIN_REQUIRED" ? 0 : 1);
    ui.clientName.textContent = value.client.name;
    ui.clientPurpose.textContent = purposes[value.client.purpose];
    ui.clientPurpose.hidden = false;
    ui.client.hidden = false;
    if (value.status === "LOGIN_REQUIRED") {
      ui.title.textContent = "登录您的账号";
      ui.description.textContent = "使用您的账号继续。登录后，再由您确认应用访问。";
      ui.login.hidden = false;
      clearPassword();
    } else if (["CONSENT_REQUIRED", "CONTEXT_SELECTION_REQUIRED"].includes(value.status)) {
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
      if (value.status === "CONTEXT_SELECTION_REQUIRED") {
        ui.title.textContent = value.contextSelection.mode === "SWITCH" ? "切换您的组织" : "选择组织，继续访问";
        ui.description.textContent = "确认此次使用的成员身份，再继续进入应用。";
        ui.selection.hidden = false;
        renderSelection(value);
      }
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
      if (pageActive) { setBusy(false); void continueAutomatically(); }
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
      if (pageActive) { setBusy(false); void continueAutomatically(); }
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
    if (action !== "restart" && !["CONSENT_REQUIRED", "CONTEXT_SELECTION_REQUIRED"].includes(interaction.status)) return;
    if (action === "restart" && !["CONSENT_REQUIRED", "CONTEXT_SELECTION_REQUIRED", "RESTART_REQUIRED"].includes(interaction.status)) return;
    const body = { action };
    if (action === "approve" && interaction.status === "CONTEXT_SELECTION_REQUIRED") {
      if (!selectedMembership) { showError("请选择此次要进入的租户和组织。"); return; }
      body.membershipId = selectedMembership;
    }
    clearMessages();
    setBusy(true, action);
    announce(action === "restart" ? "正在准备新的登录页面。" : "正在处理您的选择，请稍候。");
    try {
      const result = await request(`/oidc/interaction/${flow}`, {
        method: "POST", csrf: interaction.csrfToken, body,
      });
      if (action === "consent") {
        if (result?.continue !== true) throw new RequestFailure(502);
        await loadInteraction(true);
        return;
      }
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
      if (pageActive) { setBusy(false); void continueAutomatically(); }
    }
  }

  ui.consentForm.addEventListener("submit", (event) => {
    event.preventDefault();
    if (busy) return;
    if (interaction?.status === "CONTEXT_SELECTION_REQUIRED" && selectionStage === "tenant") {
      if (!ui.tenant.value) return;
      selectionStage = "organization"; renderMembers(); showSelectionStage(true); return;
    }
    void submitDecision(interaction?.status === "CONSENT_REQUIRED" && interaction.contextSelectionRequired ? "consent" : "approve");
  });
  ui.back.addEventListener("click", () => { if (!busy) { selectionStage = "tenant"; clearMessages(); showSelectionStage(true); } });
  ui.deny.addEventListener("click", () => { void submitDecision("deny"); });
  ui.changeAccount.addEventListener("click", () => { void submitDecision("restart"); });
  ui.restartButton.addEventListener("click", () => { void submitDecision("restart"); });
  ui.retry.addEventListener("click", () => { void refresh(true); });
  ui.tenant.addEventListener("change", () => {
    const members = interaction?.contextSelection?.members.filter((member) => member.tenantId === ui.tenant.value) || [];
    selectedMembership = members.length === 1 ? members[0].membershipId : null;
    ui.search.value = ""; renderMembers();
  });
  ui.search.addEventListener("input", renderMembers);
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
