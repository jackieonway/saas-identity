(() => {
  'use strict';
  const el = id => document.getElementById(id);
  const scopeNames = { openid: '账号标识', profile: '基本账号资料', offline_access: '保持应用登录' };
  const contextNames = { ACCOUNT_ONLY: '纯账号登录', PLATFORM_CONTEXT: '业务身份登录' };
  const idPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  let account = null, applications = [], filter = 'active', busy = false, pending = null, pendingAction = 'revoke';
  const dialog = el('revoke-dialog');
  function message(text, error = false) {
    el('message').hidden = true; el('error').hidden = true;
    if (text) { const node = el(error ? 'error' : 'message'); node.textContent = text; node.hidden = false; }
  }
  function setBusy(value) {
    busy = value;
    el('main').setAttribute('aria-busy', String(value));
    document.querySelectorAll('button,input').forEach(node => { node.disabled = value; });
  }
  async function request(url, method = 'GET', body, csrf) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      const headers = { Accept: 'application/json' };
      if (body) headers['Content-Type'] = 'application/json';
      if (csrf) headers['X-CSRF-Token'] = csrf;
      const response = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined, credentials: 'same-origin', cache: 'no-store', signal: controller.signal });
      if (!response.ok) { const error = new Error('request failed'); error.status = response.status; throw error; }
      return await response.json();
    } finally { clearTimeout(timer); }
  }
  function newUuid7() {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    let time = Date.now();
    for (let index = 5; index >= 0; index -= 1) { bytes[index] = time & 0xff; time = Math.floor(time / 256); }
    bytes[6] = (bytes[6] & 0x0f) | 0x70; bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
  }
  async function commandWithRecovery(url, method, body, csrf) {
    try { return await request(url, method, body, csrf); }
    catch (error) {
      if (Number.isInteger(error.status)) throw error;
      try {
        const receipt = await request(`/api/sso/consent-operations/${body.operationId}`);
        if (receipt?.result) return receipt.result;
      } catch (lookupError) {
        if (lookupError.status === 404) return request(url, method, body, csrf);
      }
      throw error;
    }
  }
  function signedOut() {
    account = null; applications = []; pending = null;
    if (dialog.open) dialog.close();
    el('authorization-panel').hidden = true; el('account-bar').hidden = true;
    el('application-list').replaceChildren(); el('login-panel').hidden = false;
  }
  function failure(error) {
    if (error.status === 401) { signedOut(); message('登录状态已失效，请重新登录后继续。', true); }
    else message(error.status === 403 ? '无法确认本次操作，请刷新页面后重试。' : error.status === 409 ? '授权状态已变化，请刷新列表后重试。' : '暂时无法完成操作。请稍后刷新列表，确认最新授权状态。', true);
  }
  function time(value) { return new Intl.DateTimeFormat('zh-CN', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)); }
  function confirmAction(app, action) {
    if (busy) return;
    pending = app; pendingAction = action;
    const deleting = action === 'delete';
    dialog.querySelector('.eyebrow').textContent = deleting ? '清理已撤销授权' : '取消同意组访问';
    el('revoke-title').textContent = deleting ? '删除这条授权记录？' : '撤销这组应用授权？';
    el('revoke-description').textContent = deleting ? `将从列表中隐藏「${app.displayName}」的已撤销记录。` : `「${app.displayName}」将撤销对当前账号的访问。`;
    const members = app.clients.map(client => client.displayName).join('、');
    dialog.querySelector('.revoke-detail').textContent = deleting ? '删除后，撤销记录仍作为安全凭据保留；旧授权不会恢复。再次登录时需要重新确认。' : `以下同组客户端的授权和现有凭据都会失效：${members || '当前组内客户端'}。其他应用不受影响。`;
    el('cancel-revoke').textContent = deleting ? '保留记录' : '保留授权';
    el('confirm-revoke').textContent = deleting ? '确认删除' : '确认撤销';
    dialog.showModal(); el('cancel-revoke').focus();
  }
  function render() {
    el('active-count').textContent = applications.filter(a => !a.revokedAt).length;
    el('revoked-count').textContent = applications.filter(a => a.revokedAt).length;
    el('active-tab').setAttribute('aria-pressed', String(filter === 'active'));
    el('revoked-tab').setAttribute('aria-pressed', String(filter === 'revoked'));
    const rows = applications.filter(a => filter === 'active' ? !a.revokedAt : a.revokedAt);
    el('application-list').replaceChildren(); el('empty').hidden = rows.length > 0;
    el('empty-title').textContent = filter === 'active' ? '还没有已授权的应用' : '没有已撤销的授权';
    el('empty-description').textContent = filter === 'active' ? '在应用中完成首次登录授权后，您可以在这里统一管理。' : '您撤销的应用授权会显示在这里，再次访问应用时可以重新授权。';
    for (const app of rows) {
      const card = document.createElement('article'); card.className = 'application-card';
      const initial = document.createElement('span'); initial.className = 'application-initial'; initial.textContent = Array.from(app.displayName)[0]; initial.setAttribute('aria-hidden', 'true');
      const content = document.createElement('div');
      const name = document.createElement('h2'); name.textContent = app.displayName;
      const meta = document.createElement('p'); meta.className = 'application-meta'; meta.textContent = `${app.applicationName} · ${app.environment} · ${contextNames[app.contextMode] || app.contextMode}${app.available ? '' : ' · 应用暂不可用'}${app.requiresConfirmation ? ' · 组成员变更，登录时需重新确认' : ''}`;
      const scopes = document.createElement('ul'); scopes.className = 'application-scopes'; scopes.setAttribute('aria-label', '已授权的信息');
      for (const value of app.scopes) { const li = document.createElement('li'); li.textContent = `${scopeNames[value.scope] || value.scope} · ${value.resourceKey}`; scopes.append(li); }
      const memberLine = document.createElement('p'); memberLine.className = 'application-time'; memberLine.textContent = `授权适用于：${app.clients.map(client => client.displayName).join('、') || '无可用客户端'}`;
      const date = document.createElement('p'); date.className = 'application-time'; date.textContent = `${app.revokedAt ? '撤销于 ' + time(app.revokedAt) : '授权于 ' + time(app.authorizedAt)}`;
      content.append(name, meta, scopes, memberLine, date); card.append(initial, content);
      if (!app.revokedAt) {
        const button = document.createElement('button'); button.type = 'button'; button.className = 'application-revoke'; button.textContent = '撤销授权组'; button.setAttribute('aria-label', `撤销 ${app.displayName} 的同组授权`);
        button.addEventListener('click', () => confirmAction(app, 'revoke'));
        card.append(button);
      } else {
        const actions = document.createElement('div'); actions.className = 'application-actions';
        const label = document.createElement('span'); label.className = 'revoked-label'; label.textContent = '已撤销';
        const button = document.createElement('button'); button.type = 'button'; button.className = 'application-revoke'; button.textContent = '删除记录'; button.setAttribute('aria-label', `删除 ${app.displayName} 的已撤销授权记录`);
        button.addEventListener('click', () => confirmAction(app, 'delete')); actions.append(label, button); card.append(actions);
      }
      el('application-list').append(card);
    }
  }
  async function load() {
    const session = await request('/api/sso/session');
    if (!session?.account || typeof session.account.username !== 'string' || !/^[0-9a-f]{64}$/.test(session.csrfToken)) throw new Error('invalid account');
    const value = await request('/api/sso/consents');
    if (!Array.isArray(value.consents) || value.consents.some(a => !idPattern.test(a.id) || !Number.isInteger(a.version) || a.version < 1 || typeof a.requiresConfirmation !== 'boolean' || typeof a.displayName !== 'string' || !a.displayName.trim() || typeof a.applicationName !== 'string' || !Object.hasOwn(contextNames, a.contextMode) || !Array.isArray(a.clients) || a.clients.some(c => !idPattern.test(c.id) || typeof c.displayName !== 'string') || !Array.isArray(a.scopes) || a.scopes.some(s => typeof s.resourceKey !== 'string' || typeof s.scope !== 'string') || !Number.isFinite(Date.parse(a.authorizedAt)) || (a.revokedAt !== null && !Number.isFinite(Date.parse(a.revokedAt))))) throw new Error('invalid consents');
    account = session; applications = value.consents;
    el('account-label').textContent = session.account.realName || session.account.username;
    el('account-bar').hidden = false; el('login-panel').hidden = true; el('authorization-panel').hidden = false; render();
  }
  async function refresh() {
    if (busy) return;
    setBusy(true);
    try { await load(); } catch (error) { if (error.status === 401) signedOut(); else failure(error); }
    finally { el('loading').hidden = true; setBusy(false); }
  }
  el('management-login-form').addEventListener('submit', async event => {
    event.preventDefault(); if (busy) return;
    message(''); setBusy(true);
    try {
      const challenge = await request('/api/sso/preauth');
      if (!/^[0-9a-f]{64}$/.test(challenge.csrfToken)) throw new Error('invalid challenge');
      await request('/api/sso/login', 'POST', { username: el('username').value.trim(), password: el('password').value }, challenge.csrfToken);
      el('password').value = ''; await load();
    } catch (error) { el('password').value = ''; if (error.status === 401) message('账号或密码不正确，请重新输入。',true); else failure(error); }
    finally { setBusy(false); }
  });
  el('confirm-revoke').addEventListener('click', async () => {
    if (busy || !pending || !account) return;
    const app = pending, deleting = pendingAction === 'delete'; setBusy(true); message('');
    try {
      const method = deleting ? 'DELETE' : 'POST';
      const url = `/api/sso/consents/${app.id}${deleting ? '' : '/revoke'}`;
      const result = await commandWithRecovery(url, method, { operationId:newUuid7(), expectedVersion:app.version }, account.csrfToken);
      if ((deleting ? result.deleted : result.revoked) !== true || result.consentId !== app.id) throw new Error('invalid result');
      dialog.close(); pending = null; await load(); message(deleting ? `已隐藏「${app.displayName}」的已撤销授权记录，旧凭据仍保持失效。` : `已撤销「${app.displayName}」及所有同组客户端的授权，其他应用不受影响。`);
    } catch (error) { dialog.close(); pending = null; failure(error); }
    finally { setBusy(false); el(filter + '-tab').focus(); }
  });
  dialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
  dialog.addEventListener('close', () => { pending = null; });
  el('logout').addEventListener('click', async () => {
    if (busy || !account) return; setBusy(true);
    try { await request('/api/sso/logout','POST',undefined,account.csrfToken); signedOut(); message('已退出账号，应用授权记录已保留。'); }
    catch (error) { failure(error); } finally { setBusy(false); }
  });
  for (const value of ['active', 'revoked']) el(value+'-tab').addEventListener('click', () => { if (!busy) { filter = value; render(); } });
  el('refresh').addEventListener('click', () => { message(''); void refresh(); });
  window.addEventListener('pageshow', event => { if (event.persisted) void refresh(); });
  window.addEventListener('pagehide', () => { el('password').value = ''; });
  void refresh();
})();
