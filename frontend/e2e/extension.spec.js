// Real built extension, isolated browser profile, synthetic pages only.
// No owner, cloud grants, vault keys or user's installed browser are accessed.
import {test as base,expect,chromium} from '@playwright/test';
import path from 'node:path';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';

const extension=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../companion/extension/dist');
const version=JSON.parse(readFileSync(path.join(extension,'manifest.json'),'utf8')).version;
const origin='https://login.sentinelops.test';
const login=`<form action="/session"><label>Username<input name="username" autocomplete="username"></label><label>Password<input type="password" autocomplete="current-password"></label><button>Sign in</button></form>`;
const pageHtml=body=>`<!doctype html><html><body>${body}<script>window.submissions=0;document.addEventListener('submit',e=>{e.preventDefault();window.submissions++})</script></body></html>`;

const test=base.extend({
  installed: async({},use)=>{
    const context=await chromium.launchPersistentContext('',{
      channel:'chromium',headless:true,
      args:[`--disable-extensions-except=${extension}`,`--load-extension=${extension}`],
    });
    // Intercept even DNS/TLS for fixture documents. Everything else is blocked;
    // this is not a scan, login or acceptance test of a public website.
    const unexpected=[];
    await context.route('**/*',async route=>{
      const url=new URL(route.request().url());
      if(url.protocol==='chrome-extension:')return route.continue();
      if(url.origin!==origin){unexpected.push(url.origin);return route.abort();}
      let body=login;
      if(url.pathname==='/cross-action')body=login.replace('action="/session"','action="https://other.sentinelops.test/session"');
      if(url.pathname==='/signup')body=login.replace('current-password','new-password');
      if(url.pathname==='/otp')body='<form action="/verify"><label>Code<input autocomplete="one-time-code" inputmode="numeric"></label><button>Verify</button></form>';
      if(url.pathname==='/frame')body='<iframe src="/login" title="Embedded login"></iframe>';
      await route.fulfill({status:200,contentType:'text/html',body:pageHtml(body)});
    });
    try{
      const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker');
      const page=await context.newPage();
      const send=async message=>{
        await page.bringToFront();
        return worker.evaluate(async message=>{
          const [tab]=await chrome.tabs.query({active:true,currentWindow:true});
          return chrome.tabs.sendMessage(tab.id,message,{frameId:0});
        },message);
      };
      const open=async pathname=>{
        await page.goto(origin+pathname);
        await expect.poll(async()=>{try{return (await send({type:'inspect-login',origin})).version;}catch{return null;}}).toBe(version);
      };
      await use({context,worker,page,send,open});
      expect(unexpected,'No external website/cloud traffic is allowed').toEqual([]);
    }finally{await context.close();}
  },
});

test('built service worker and popup load without an account',async({installed})=>{
  const {worker,page}=installed;
  expect(await worker.evaluate(()=>globalThis.sentinelMonitorProtocol)).toBe('sentinel-site-monitor/v1');
  const id=new URL(worker.url()).host;
  await page.goto(`chrome-extension://${id}/popup.html`);
  await expect(page.getByText('SentinelOps',{exact:true})).toBeVisible();
  await expect(page.getByRole('heading',{name:'Connect your cloud vault',exact:true})).toBeVisible();
});

test('real content-script messaging fills one exact-origin login without submitting',async({installed})=>{
  const {page,send,open}=installed;
  await open('/login');
  const inspected=await send({type:'inspect-login',origin});
  expect(inspected.ok).toBe(true);expect(inspected.version).toBe(version);
  const result=await send({type:'fill-login',entry:{origin,username:'practice-fixture',password:'Disposable-e2e-password!'}});
  expect(result).toMatchObject({ok:true,filled:'login'});
  await expect(page.getByLabel('Username')).toHaveValue('practice-fixture');
  await expect(page.getByLabel('Password')).toHaveValue('Disposable-e2e-password!');
  expect(await page.evaluate(()=>window.submissions)).toBe(0);
});

test('wrong-origin credentials and cross-origin form actions are rejected',async({installed})=>{
  const {page,send,open}=installed;
  await open('/login');
  expect(await send({type:'fill-login',entry:{origin:'https://other.sentinelops.test',username:'fixture',password:'Disposable-e2e-password!'}})).toMatchObject({ok:false,reason:'origin'});
  await expect(page.getByLabel('Username')).toHaveValue('');
  await expect(page.getByLabel('Password')).toHaveValue('');
  await open('/cross-action');
  expect(await send({type:'inspect-login',origin})).toMatchObject({ok:false,reason:'form_action'});
});

test('signup and embedded login forms are not treated as main-page sign-in',async({installed})=>{
  const {page,send,open}=installed;
  for(const pathname of ['/signup','/frame']){
    await open(pathname);
    expect((await send({type:'inspect-login',origin})).ok).toBe(false);
  }
  await expect(page.frameLocator('iframe').getByLabel('Password')).toHaveValue('');
});

test('explicit OTP fill stays within its exact origin and never submits',async({installed})=>{
  const {page,send,open}=installed;
  await open('/otp');
  expect(await send({type:'inspect-otp',origin})).toMatchObject({ok:true});
  expect(await send({type:'fill-otp',origin,code:'123456'})).toMatchObject({ok:true});
  await expect(page.getByLabel('Code')).toHaveValue('123456');
  expect(await page.evaluate(()=>window.submissions)).toBe(0);
});

test('agency popup approves one two-vault plan and follows it to its report without repeat approval',async({installed})=>{
  const {context,worker,page}=installed;
  const client='c'.repeat(24),person='d'.repeat(24),workflow='a'.repeat(24);
  const vaults=['b'.repeat(24),'e'.repeat(24)];
  const connection={origin,kind:'access',token:'fixtureOnlyAccessToken'.repeat(3)};
  const calls=[];
  let run=null,reads=0;
  const map={clients:[{id:client,name:'Disposable agency client'}],systems:vaults.map((id,index)=>({id,name:`Client vault ${index+1}`})),grants:vaults.map(vault=>({client,person_id:person,email:'departing@example.test',system:vault}))};
  // This route is deliberately mock-only; it never contacts a deployed app.
  await context.route(origin+'/api/companion/access/**',async route=>{
    const req=route.request(),url=new URL(req.url()),action=url.pathname.split('/api/companion/access/')[1];
    const cors={'access-control-allow-origin':'*','access-control-allow-headers':'Authorization, Content-Type','access-control-allow-methods':'GET, POST, OPTIONS'};
    if(req.method()==='OPTIONS')return route.fulfill({status:204,headers:cors});
    const body=req.postDataJSON();calls.push({action,method:req.method(),body});
    expect(req.headers().authorization).toBe('Bearer '+connection.token);
    expect(req.headers().cookie).toBeUndefined();
    let result;
    if(action==='context')result=map;
    else if(action==='workflows'&&req.method()==='POST'){
      expect(body).toEqual({client_id:client,person_id:person,dry_run:false});
      run={id:workflow,client,person,status:'awaiting_approval',plan_digest:'f'.repeat(64),plan:{dry_run:false,vaults:vaults.map(vault=>({vault}))},steps:vaults.map(id=>({id,action:'revoke',status:'pending'})),coverage:'Selected vault memberships only.'};result=run;
    }else if(action===`workflows/${workflow}/approve`){
      expect(body).toEqual({plan_digest:'f'.repeat(64),approved:true,password:'Disposable-approval-fixture!',code:'123456'});
      run.status='queued';result={ok:true};
    }else if(action==='workflows'){
      if(run&&run.status!=='awaiting_approval'){
        reads++;
        if(reads===2)run.status='running';
        if(reads>=3){run.status='complete';run.steps.forEach(step=>{step.status='complete';});}
      }
      result={workflows:run?[run]:[]};
    }else if(action===`workflows/${workflow}/report`)result={audit:{valid:true},limitations:'Fixture server reports selected vault steps only. External accounts are unverified.'};
    else throw new Error('Unexpected agency fixture request: '+action);
    await route.fulfill({status:200,headers:cors,contentType:'application/json',body:JSON.stringify(result)});
  });
  await worker.evaluate(connection=>chrome.storage.local.set({accessConnection:connection}),connection);
  await page.goto(`chrome-extension://${new URL(worker.url()).host}/popup.html`);
  const home=page.getByRole('region',{name:'Client access workflows'});
  await expect(home).toBeVisible();
  await expect(home).toContainText('What needs doing?');
  await home.getByRole('combobox',{name:'Client',exact:true}).selectOption(client);
  await home.getByRole('combobox',{name:'Person',exact:true}).selectOption(person);
  await home.getByLabel('Preview only; make no changes').uncheck();
  await home.getByRole('button',{name:'Prepare offboarding plan'}).click();
  await expect(home.getByText('Client vault 1',{exact:true})).toBeVisible();
  await expect(home.getByText('Client vault 2',{exact:true})).toBeVisible();
  await home.getByLabel('Current account password').fill('Disposable-approval-fixture!');
  await home.getByLabel('Unused MFA or recovery code').fill('123456');
  await home.getByLabel('I approve this exact access removal plan.').check();
  await home.getByRole('button',{name:'Approve plan'}).click();
  await expect(home.getByText(/Approved. Waiting for the server worker/)).toBeVisible();
  await expect(home.getByText(/Running approved steps automatically/)).toBeVisible({timeout:10000});
  await expect(home.getByText(/The selected vault steps are verified/)).toBeVisible({timeout:10000});
  await home.getByRole('button',{name:'View evidence report'}).click();
  await expect(home.getByRole('heading',{name:'Vault offboarding evidence'})).toBeVisible();
  await expect(home.getByText('Fixture server reports selected vault steps only. External accounts are unverified.',{exact:true})).toBeVisible();
  expect(calls.filter(call=>call.method==='POST').map(call=>call.action)).toEqual(['workflows',`workflows/${workflow}/approve`]);
  expect(calls.filter(call=>JSON.stringify(call.body||{}).includes('Disposable-approval-fixture!'))).toHaveLength(1);
});
