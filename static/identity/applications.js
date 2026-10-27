(() => {
  'use strict';
  const el = id => document.getElementById(id);
  const scopeNames = { openid: '账号标识', profile: '基本账号资料', offline_access: '保持应用登录' };
  const purposes = { PLATFORM_CONSOLE: '员工控制台', CUSTOMER_PORTAL: '客户门户', ACCOUNT: '账号应用' };
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
    dialog.querySelector('.eyebrow').textContent = deleting ? '清理已撤销授权' : '取消应用访问';
    el('revoke-title').textContent = deleting ? '删除这条授权记录？' : '撤销这份授权？';
    el('revoke-description').textContent = deleting ? `将从列表中删除「${app.name}」的已撤销授权记录。` : `您将取消「${app.name}」对当前账号的访问授权。`;
    dialog.querySelector('.revoke-detail').textContent = deleting ? '删除后，应用仍无权访问您的账号。下次访问该应用时，需要重新授权。' : '该应用当前登录会失效。您仍可以在下次访问时重新授权，其他应用不受影响。';
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
      const initial = document.createElement('span'); initial.className = 'application-initial'; initial.textContent = Array.from(app.name)[0]; initial.setAttribute('aria-hidden', 'true');
      const content = document.createElement('div');
      const name = document.createElement('h2'); name.textContent = app.name;
      const meta = document.createElement('p'); meta.className = 'application-meta'; meta.textContent = `${purposes[app.purpose]}${app.available ? '' : ' · 应用已停用'}`;
      const scopes = document.createElement('ul'); scopes.className = 'application-scopes'; scopes.setAttribute('aria-label', '已授权的信息');
      for (const value of app.scopes) { const li = document.createElement('li'); li.textContent = scopeNames[value]; scopes.append(li); }
      const date = document.createElement('p'); date.className = 'application-time'; date.textContent = `${app.revokedAt ? '撤销于 ' + time(app.revokedAt) : '授权于 ' + time(app.approvedAt)}`;
      content.append(name, meta, scopes, date); card.append(initial, content);
      if (!app.revokedAt) {
        const button = document.createElement('button'); button.type = 'button'; button.className = 'application-revoke'; button.textContent = '撤销授权'; button.setAttribute('aria-label', `撤销 ${app.name} 的授权`);
        button.addEventListener('click', () => confirmAction(app, 'revoke'));
        card.append(button);
      } else {
        const actions = document.createElement('div'); actions.className = 'application-actions';
        const label = document.createElement('span'); label.className = 'revoked-label'; label.textContent = '已撤销';
        const button = document.createElement('button'); button.type = 'button'; button.className = 'application-revoke'; button.textContent = '删除记录'; button.setAttribute('aria-label', `删除 ${app.name} 的已撤销授权记录`);
        button.addEventListener('click', () => confirmAction(app, 'delete')); actions.append(label, button); card.append(actions);
      }
      el('application-list').append(card);
    }
  }
  async function load() {
    const session = await request('/api/sso/session');
    if (!session?.account || typeof session.account.username !== 'string' || !/^[0-9a-f]{64}$/.test(session.csrfToken)) throw new Error('invalid account');
    const value = await request('/api/sso/applications');
    if (!Array.isArray(value.applications) || value.applications.some(a => !idPattern.test(a.clientId) || typeof a.name !== 'string' || !a.name.trim() || !Object.hasOwn(purposes, a.purpose) || !Array.isArray(a.scopes) || !a.scopes.every(s => Object.hasOwn(scopeNames,s)) || !Number.isFinite(Date.parse(a.approvedAt)) || (a.revokedAt !== null && !Number.isFinite(Date.parse(a.revokedAt))))) throw new Error('invalid approvals');
    account = session; applications = value.applications;
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
      const result = await request(`/api/sso/applications/${app.clientId}${deleting ? '' : '/revoke'}`, deleting ? 'DELETE' : 'POST', undefined, account.csrfToken);
      if ((deleting ? result.deleted : result.revoked) !== true || result.clientId !== app.clientId) throw new Error('invalid result');
      dialog.close(); pending = null; await load(); message(deleting ? `已删除「${app.name}」的已撤销授权记录。再次访问仍需重新授权。` : `已撤销「${app.name}」的授权。下次访问该应用时需要重新确认。`);
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
