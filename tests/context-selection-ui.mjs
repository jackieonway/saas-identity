// Production UI and explicit HTTP fixtures; database persistence is tested separately.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile,mkdir,writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'), executable=process.env.IDENTITY_TEST_BROWSER_EXECUTABLE;
assert(executable&&path.isAbsolute(executable),'Set IDENTITY_TEST_BROWSER_EXECUTABLE');
const reportDir=path.join(root,'artifacts','context-selection');await mkdir(reportDir,{recursive:true});
const id=n=>`019a1163-0000-7000-8000-${n.toString(16).padStart(12,'0')}`,flow=id(1);
const member=(n,t,name,type='EMPLOYEE')=>({membershipId:id(n),userId:id(2),tenantId:id(t),organizationId:id(n+100),memberType:type,identityVersion:'1',tenantName:t===10?'青禾商贸':'远山服务',organizationName:name,organizationPath:`总部 / ${name}`});
let scenario,posts=[],consented=false,revoked=false,deleted=false;
const view=()=>scenario.restart?{status:'RESTART_REQUIRED',client:{name:'企业工作台',purpose:'PLATFORM_CONSOLE'},account:null,csrfToken:'a'.repeat(64),scopes:['openid','profile'],expiresAt:new Date(Date.now()+300000).toISOString()}:({status:consented?'CONTEXT_SELECTION_REQUIRED':'CONSENT_REQUIRED',contextSelectionRequired:true,consentRemembered:consented,client:{name:'企业工作台',purpose:scenario.purpose||'PLATFORM_CONSOLE'},account:{id:id(2),username:'lin.yue',realName:'林悦'},csrfToken:'a'.repeat(64),scopes:['openid','profile'],expiresAt:new Date(Date.now()+300000).toISOString(),contextSelection:consented?{mode:scenario.mode||'LOGIN',members:scenario.members,expiresAt:new Date(Date.now()+120000).toISOString()}:null});
const assets={'/sso/login':['login.html','text/html'],'/oauth/login':['login.html','text/html'],'/sso/assets/identity.js':['identity.js','text/javascript'],'/sso/assets/identity.css':['identity.css','text/css'],'/sso/applications':['applications.html','text/html'],'/sso/assets/applications.js':['applications.js','text/javascript'],'/sso/assets/applications.css':['applications.css','text/css']};
const server=createServer(async(req,res)=>{try{
  const url=new URL(req.url,'http://localhost');res.setHeader('Cache-Control','no-store');
  if(url.pathname.startsWith('/oauth/interaction/')){
    res.setHeader('Content-Type','application/json');if(req.method==='GET'){res.end(JSON.stringify(view()));return;}
    let raw='';for await(const chunk of req)raw+=chunk;assert.equal(req.headers['x-csrf-token'],'a'.repeat(64));const body=JSON.parse(raw);posts.push(body);
    if(body.action==='restart'){res.end(JSON.stringify({redirectTo:`/oauth/login?flow=${id(99)}`}));return;}
    if(body.action==='consent'){consented=true;res.end(JSON.stringify({continue:true}));return;}
    res.end(JSON.stringify({redirectTo:'https://platform.example.test/auth/callback?code=fixture&state=fixture'}));return;
  }
  if(url.pathname==='/api/sso/session'){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({account:{username:'lin.yue',realName:'林悦'},csrfToken:'a'.repeat(64)}));return;}
  if(url.pathname==='/api/sso/consents'){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({consents:deleted?[]:[{id:id(7),version:1,generation:1,requiresConfirmation:false,displayName:'企业工作台',applicationName:'企业平台',purpose:'Platform console access',environment:'production',contextMode:'PLATFORM_CONTEXT',authorizedAt:'2026-10-27T10:00:00Z',revokedAt:revoked?'2026-10-27T11:00:00Z':null,available:true,clients:[{id:id(8),displayName:'企业工作台 Web'}],scopes:[{resourceKey:'userinfo',audience:'https://auth.example.test/oauth/userinfo',scope:'openid'},{resourceKey:'userinfo',audience:'https://auth.example.test/oauth/userinfo',scope:'profile'}]}]}));return;}
  if(url.pathname===`/api/sso/consents/${id(7)}/revoke`){let raw='';for await(const chunk of req)raw+=chunk;assert.equal(req.headers['x-csrf-token'],'a'.repeat(64));assert.equal(JSON.parse(raw).expectedVersion,1);revoked=true;res.setHeader('Content-Type','application/json');res.end(JSON.stringify({revoked:true,consentId:id(7)}));return;}
  if(url.pathname===`/api/sso/consents/${id(7)}`&&req.method==='DELETE'){let raw='';for await(const chunk of req)raw+=chunk;assert.equal(req.headers['x-csrf-token'],'a'.repeat(64));assert.equal(JSON.parse(raw).expectedVersion,1);assert(revoked);deleted=true;res.setHeader('Content-Type','application/json');res.end(JSON.stringify({deleted:true,consentId:id(7)}));return;}
  const asset=assets[url.pathname];if(asset){res.setHeader('Content-Type',asset[1]+'; charset=utf-8');res.setHeader('Content-Security-Policy',"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");res.end(await readFile(path.join(root,'static/identity',asset[0])));return;}
  res.statusCode=204;res.end();
}catch{res.statusCode=500;res.end('fixture failure');}});
await new Promise(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${server.address().port}`,checks=[];let browser;
async function test(name,fixture,run,viewport={width:1440,height:960}){
  scenario=fixture;posts=[];consented=fixture.remembered||false;revoked=false;deleted=false;
  const context=await browser.newContext({viewport,reducedMotion:'reduce'}),page=await context.newPage(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.route('https://platform.example.test/**',r=>r.fulfill({contentType:'text/html',body:'<p>Fixture callback</p>'}));
  try{await page.goto(`${origin}${fixture.pagePath||'/oauth/login'}?flow=${flow}`);await run(page);assert.deepEqual(errors,[]);checks.push({name,status:'passed'});}finally{await context.close();}
}
async function consent(page){await page.locator('#permissions').waitFor({state:'visible'});await page.locator('#consent-allow').click();}
try{
  browser=await chromium.launch({headless:true,executablePath:executable,args:['--no-proxy-server']});const two=[member(20,10,'华东运营中心'),member(21,10,'南区服务中心')],many=[...two,member(22,11,'远山总部')];
  await test('sso-login-alias-uses-canonical-interactions',{pagePath:'/sso/login',remembered:true,members:two},async p=>{await p.locator('#organization-choices').waitFor({state:'visible'});assert.deepEqual(posts,[]);await p.locator('input[name=context-membership]').first().check();await p.locator('#consent-allow').click();await p.waitForURL('https://platform.example.test/**');assert.deepEqual(posts,[{action:'approve',membershipId:id(20)}]);});
  await test('restart-follows-canonical-login-path',{pagePath:'/sso/login',restart:true,members:[]},async p=>{await p.locator('#restart-panel').waitFor({state:'visible'});await p.locator('#restart-button').click();await p.waitForURL(`${origin}/oauth/login?flow=${id(99)}`);assert.deepEqual(posts,[{action:'restart'}]);});
  await test('single-tenant-skips-tenant-step',{members:two},async p=>{
    await consent(p);await p.locator('#organization-choices').waitFor({state:'visible'});assert.equal(await p.locator('#tenant-step').isVisible(),false);assert.equal(await p.locator('#selection-back').isVisible(),false);assert.equal(await p.locator('#auth-steps').isVisible(),false);assert.deepEqual(posts,[{action:'consent'}]);
    await p.screenshot({path:path.join(reportDir,'desktop.png'),fullPage:true});await p.locator('input[name=context-membership]').first().check();await p.locator('#consent-allow').click();await p.waitForURL('https://platform.example.test/**');assert.deepEqual(posts,[{action:'consent'},{action:'approve',membershipId:id(20)}]);
  });
  await test('single-organization-enters-after-first-consent',{members:[two[0]]},async p=>{await consent(p);await p.waitForURL('https://platform.example.test/**');assert.deepEqual(posts,[{action:'consent'},{action:'approve',membershipId:id(20)}]);});
  await test('remembered-single-identity-needs-no-clicks',{remembered:true,members:[two[0]]},async p=>{await p.waitForURL('https://platform.example.test/**');assert.deepEqual(posts,[{action:'approve',membershipId:id(20)}]);});
  await test('remembered-approval-survives-reload-search-does-not-auto-select',{remembered:true,members:two},async p=>{await p.locator('#organization-choices').waitFor({state:'visible'});await p.reload();await p.locator('#organization-choices').waitFor({state:'visible'});assert.equal(await p.locator('#permissions').isVisible(),false);await p.locator('#selection-search').fill('南区');assert.equal(await p.locator('input[name=context-membership]').count(),1);assert.deepEqual(posts,[]);});
  await test('tenant-with-one-organization-enters-directly',{remembered:true,members:many},async p=>{await p.locator('#tenant-choices button').filter({hasText:'远山服务'}).click();await p.waitForURL('https://platform.example.test/**');assert.deepEqual(posts,[{action:'approve',membershipId:id(22)}]);});
  await test('multiple-tenants-and-organizations-require-choice',{remembered:true,members:many},async p=>{await p.locator('#tenant-choices button').filter({hasText:'青禾商贸'}).click();await p.locator('#organization-choices').waitFor({state:'visible'});assert.equal(await p.locator('input[name=context-membership]').count(),2);assert.deepEqual(posts,[]);await p.locator('#selection-back').click();assert.equal(await p.locator('#tenant-choices').isVisible(),true);});
  await test('no-members-never-auto-approves',{remembered:true,members:[]},async p=>{await p.locator('#selection-empty').waitFor({state:'visible'});assert.deepEqual(posts,[]);await p.locator('#consent-deny').click();await p.waitForURL('https://platform.example.test/**');assert.deepEqual(posts,[{action:'deny'}]);});
  await test('customer-and-hostile-names-render-as-text',{remembered:true,purpose:'CUSTOMER_PORTAL',members:[member(30,10,'<img src=x onerror=alert(1)>','CUSTOMER'),member(31,10,'客户组织','CUSTOMER')]},async p=>{await p.locator('#organization-choices').waitFor({state:'visible'});assert.equal(await p.locator('#selection-members img').count(),0);assert.equal(await p.locator('.member-choice-name').first().textContent(),'<img src=x onerror=alert(1)>');assert.match(await p.locator('.member-choice-type').first().textContent(),/客户身份/);});
  await test('mobile-single-tenant-multiple-organizations',{remembered:true,members:two},async p=>{await p.locator('#organization-choices').waitFor({state:'visible'});assert.equal(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);await p.screenshot({path:path.join(reportDir,'mobile.png'),fullPage:true});},{width:390,height:844});
  await test('application-manager-confirmation-and-revoked-history',{remembered:true,members:two},async p=>{await p.goto(origin+'/sso/applications');await p.getByRole('button',{name:'撤销 企业工作台 的同组授权'}).click();await p.getByRole('button',{name:'保留授权'}).click();assert.equal(revoked,false);await p.getByRole('button',{name:'撤销 企业工作台 的同组授权'}).click();await p.getByRole('button',{name:'确认撤销'}).click();await p.locator('#message').waitFor({state:'visible'});assert.equal(revoked,true);await p.locator('#revoked-tab').click();assert.equal(await p.locator('.application-card').count(),1);await p.screenshot({path:path.join(reportDir,'applications.png'),fullPage:true});});
  await test('revoked-record-delete-cancel-confirm-empty-state',{remembered:true,members:two},async p=>{
    await p.goto(origin+'/sso/applications');await p.getByRole('button',{name:'撤销 企业工作台 的同组授权'}).click();await p.getByRole('button',{name:'确认撤销'}).click();await p.locator('#message').waitFor({state:'visible'});await p.locator('#revoked-tab').click();
    await p.getByRole('button',{name:'删除 企业工作台 的已撤销授权记录'}).click();await p.getByRole('button',{name:'保留记录'}).click();assert.equal(deleted,false);
    await p.getByRole('button',{name:'删除 企业工作台 的已撤销授权记录'}).click();await p.getByRole('button',{name:'确认删除'}).click();await p.getByText('已隐藏「企业工作台」的已撤销授权记录，旧凭据仍保持失效。',{exact:true}).waitFor({state:'visible'});
    assert.equal(deleted,true);assert.equal(await p.locator('.application-card').count(),0);assert.equal(await p.locator('#revoked-count').textContent(),'0');assert.equal(await p.locator('#empty').isVisible(),true);
  });
  await writeFile(path.join(reportDir,'report.json'),JSON.stringify({status:'passed',backend:'Explicit HTTP fixtures; real persistence checked separately',browser:await browser.version(),checks},null,2));console.log(JSON.stringify({status:'passed',checks:checks.length,reportDirectory:reportDir}));
}finally{if(browser)await browser.close();await new Promise(r=>server.close(r));}
