// Actual browser crypto and actual API, two registered disposable accounts.
// No operator profiles, cloud credentials, model calls or public site requests.
import {test,expect,chromium} from '@playwright/test';
import {readFileSync,readdirSync} from 'node:fs';
import {join} from 'node:path';
import {createHmac} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const origin='http://127.0.0.1:18222';
const password='Disposable-Only!harbor-river-orbit-79';
const master='Disposable!Cedar8-Beacon#Sharing64';
function totp(secret,at=Date.now()){
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';let bits='';
  for(const c of secret.replace(/=+$/,''))bits+=alphabet.indexOf(c).toString(2).padStart(5,'0');
  const key=Buffer.from(bits.match(/.{8}/g).map(v=>parseInt(v,2)));
  const step=Buffer.alloc(8);step.writeBigUInt64BE(BigInt(Math.floor(at/30000)));
  const hash=createHmac('sha1',key).update(step).digest(),offset=hash[19]&15;
  return ((hash.readUInt32BE(offset)&0x7fffffff)%1000000).toString().padStart(6,'0');
}
async function get(context,path){const response=await context.request.get(origin+'/api'+path);expect(response.ok(),path).toBe(true);return response.json();}
async function post(context,path,body){
  const me=await context.request.get(origin+'/api/me');
  const headers={Origin:origin,...(me.ok()?{'X-CSRF-Token':(await me.json()).csrf}:{})};
  const response=await context.request.post(origin+'/api'+path,{data:body,headers});
  // Error text may contain fixture data but never operator credentials.
  expect(response.ok(),path+' '+(response.ok()?'':await response.text())).toBe(true);return response.json();
}
async function sharedPage(page){await page.goto(origin);await page.getByRole('button',{name:'Vaults',exact:true}).click();await page.getByRole('button',{name:'Shared workspace vaults',exact:true}).click();}
async function unlock(page){
  if(await page.getByRole('button',{name:'Lock shared vaults',exact:true}).isVisible())return;
  await page.getByLabel('Sharing passphrase',{exact:true}).fill(master);
  const confirm=page.getByLabel('Confirm sharing passphrase',{exact:true});
  if(await confirm.isVisible()){await confirm.fill(master);await page.getByRole('button',{name:'Create encrypted identity',exact:true}).click();}
  else await page.getByRole('button',{name:'Unlock sharing identity',exact:true}).click();
  await expect(page.getByRole('button',{name:'Lock shared vaults',exact:true})).toBeVisible();
}
async function openCompanion(companion,connection,connections,trusted){
  await companion.worker.evaluate(({connection,connections})=>chrome.storage.local.set({connection,connections}),{connection,connections});
  const page=await companion.context.newPage();
  await page.goto(`chrome-extension://${new URL(companion.worker.url()).host}/popup.html`);
  await page.getByLabel('Sharing passphrase',{exact:true}).fill(master);
  if(!connection.ownerIsSelf)await page.getByLabel('Verified owner fingerprint',{exact:true}).fill(trusted);
  await page.getByRole('button',{name:'Unlock',exact:true}).click();
  if(!connection.ownerIsSelf)await expect(page.getByText('Unlocked · this popup only',{exact:true})).toBeVisible();
  return page;
}
test('two real accounts share two vaults; approved offboarding rotates keys and rejects cached member keys',async({browser})=>{
  const owner=await browser.newContext(),member=await browser.newContext();
  let companion;
  try{
    for(const context of [owner,member])await context.route('**/*',route=>new URL(route.request().url()).origin===origin?route.continue():route.abort());
    const bootstrap=readFileSync(join(process.env.SENTINELOPS_E2E_DATA,'.bootstrap-token'),'utf8').trim();
    await post(owner,'/setup',{email:'owner@browser.example.test',password,token:bootstrap,workspace_name:'Browser acceptance agency'});
    const enrollment=await post(owner,'/mfa/setup',{password});
    const factors=await post(owner,'/mfa/enable',{code:totp(enrollment.secret)});
    const invite=await post(owner,'/invites',{email:'member@browser.example.test',role:'reviewer'});
    await post(member,'/join',{email:'member@browser.example.test',password,token:invite.token});
    const ownerPage=await owner.newPage(),memberPage=await member.newPage();
    await sharedPage(ownerPage);await unlock(ownerPage);
    await sharedPage(memberPage);await unlock(memberPage);
    const own=await get(owner,'/me'),other=await get(member,'/me');
    const ownerIdentity=(await get(owner,'/sharing/identity')).identity;
    const memberIdentity=(await get(member,'/sharing/identity')).identity;
    const extensionPath=fileURLToPath(new URL('../../companion/extension/dist',import.meta.url));
    const extensionContext=await chromium.launchPersistentContext('',{channel:'chromium',headless:true,args:[`--disable-extensions-except=${extensionPath}`,`--load-extension=${extensionPath}`]});
    await extensionContext.route('**/*',route=>{const url=new URL(route.request().url());return url.origin===origin||url.protocol==='chrome-extension:'?route.continue():route.abort();});
    const worker=extensionContext.serviceWorkers()[0]||await extensionContext.waitForEvent('serviceworker');
    companion={context:extensionContext,worker,connections:[]};
    const cache=await member.newPage();await cache.goto(origin);
    const vaults=[];
    for(let index=1;index<=2;index++){
      const name='Acceptance client vault '+index;
      await unlock(ownerPage);
      await ownerPage.getByLabel('New shared vault name').fill(name);
      await ownerPage.getByRole('button',{name:'Create shared vault',exact:true}).click();
      await ownerPage.getByRole('button',{name:'Verify and open shared vault',exact:true}).click();
      await ownerPage.getByLabel('Account label',{exact:true}).fill('Disposable credential '+index);
      await ownerPage.getByLabel('Website origin',{exact:true}).fill('https://example.test');
      await ownerPage.getByLabel('Username',{exact:true}).fill('public-fixture');
      await ownerPage.getByLabel('Password',{exact:true}).fill('Disposable-before-removal!'+index);
      await ownerPage.getByRole('button',{name:'Encrypt and save account',exact:true}).click();
      await expect(ownerPage.getByText('Encrypted changes saved.',{exact:true})).toBeVisible();
      await ownerPage.getByRole('combobox',{name:/^Teammate/}).selectOption(other.id);
      await ownerPage.getByLabel('Recipient fingerprint verified through another channel',{exact:true}).fill(memberIdentity.fingerprint);
      await ownerPage.getByRole('combobox',{name:/^Vault role/}).selectOption('editor');
      await ownerPage.getByRole('button',{name:'Send encrypted invitation',exact:true}).click();
      await memberPage.reload();await memberPage.getByRole('button',{name:'Shared workspace vaults',exact:true}).click();await unlock(memberPage);
      await memberPage.getByRole('button',{name:name+' · editor · invitation',exact:true}).click();
      await memberPage.getByLabel('Verified owner fingerprint',{exact:true}).fill(ownerIdentity.fingerprint);
      await memberPage.getByRole('button',{name:'Verify and accept invitation',exact:true}).click();
      await expect(memberPage.getByText('Invitation accepted. Verify and open the vault to read its encrypted contents.',{exact:true})).toBeVisible();
      await memberPage.getByLabel('Verified owner fingerprint',{exact:true}).fill(ownerIdentity.fingerprint);
      await memberPage.getByRole('button',{name:'Verify and open shared vault',exact:true}).click();
      await expect(memberPage.locator('article.entry-card').getByText('Disposable credential '+index,{exact:true})).toBeVisible();
      const id=(await get(owner,'/team-vaults')).vaults.find(v=>v.name===name).id;vaults.push({id,name});
      const pair=await post(member,'/companions',{kind:'shared',vault_id:id,label:'Isolated browser '+index,password});
      const connection={origin,token:pair.token,vaultId:id,vaultName:name,vaultKind:'shared',ownerFingerprint:ownerIdentity.fingerprint,ownerIsSelf:false};
      companion.connections.push(connection);
      const popup=await openCompanion(companion,connection,companion.connections,ownerIdentity.fingerprint);
      await popup.getByText('Save a login manually',{exact:true}).click();
      await popup.getByLabel('HTTPS website origin',{exact:true}).fill('https://example.test');
      await popup.getByLabel('Username',{exact:true}).fill('public-companion');
      await popup.getByLabel('Password',{exact:true}).fill('Disposable-companion-secret!'+index);
      await popup.getByRole('button',{name:'Encrypt and save',exact:true}).click();
      await expect(popup.getByText('Encrypted and saved. No plaintext was sent to the server.',{exact:true})).toBeVisible();
      if(index===1){
        await popup.getByText('Add an authenticator account',{exact:true}).click();
        await popup.getByLabel('Authenticator account name',{exact:true}).fill('Disposable authenticator');
        await popup.getByLabel('Setup key or TOTP URI',{exact:true}).fill('JBSWY3DPEHPK3PXP');
        await popup.getByRole('button',{name:'Encrypt and add authenticator',exact:true}).click();
        await expect(popup.getByText(/Authenticator saved\. Use Show code/)).toBeVisible();
      }
      await popup.close();
      // A new popup must unlock again and fetch persisted ciphertext.
      const reopened=await openCompanion(companion,connection,companion.connections,ownerIdentity.fingerprint);
      if(index===1){
        const before=Date.now();await reopened.getByRole('button',{name:'Show code',exact:true}).click();
        const code=await reopened.locator('p.code').innerText();
        expect([totp('JBSWY3DPEHPK3PXP',before),totp('JBSWY3DPEHPK3PXP')]).toContain(code);
      }
      const saved=await worker.evaluate(()=>chrome.storage.local.get(null));
      for(const value of [master,'Disposable-companion-secret!'+index,'JBSWY3DPEHPK3PXP'])expect(JSON.stringify(saved)).not.toContain(value);
      await reopened.close();
      const team=await get(member,'/team-vaults/'+id);
      const result=await cache.evaluate(async({team,record,user,master,trusted})=>{
        const crypto=await import('/src/sharing-crypto.js');
        const identity=await crypto.unlockSharingIdentity(user,record,master);
        const opened=await crypto.openTeamVault(team,identity,trusted);
        window.acceptanceCachedHandles ||= {};
        window.acceptanceCachedHandles[team.id]=opened.handle;
        const raw=new Uint8Array(await identity.unwrap(team.grant));
        window.acceptanceCachedKeys ||= {};
        try{window.acceptanceCachedKeys[team.id]=await window.crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);}finally{raw.fill(0);}
        return opened.entries.length;
      },{team,record:memberIdentity,user:other.id,master,trusted:ownerIdentity.fingerprint});
      expect(result).toBe(index===1?3:2);
    }
    const client=await post(owner,'/clients',{name:'Browser acceptance client'});
    for(const {id} of vaults)await post(owner,`/clients/${client.id}/vaults`,{vault_id:id});
    const ownerConnections=[];
    for(let index=0;index<vaults.length;index++){
      const vault=vaults[index],pair=await post(owner,'/companions',{kind:'shared',vault_id:vault.id,label:'Isolated owner '+index,password,code:factors.recovery_codes[index+1]});
      ownerConnections.push({origin,token:pair.token,vaultId:vault.id,vaultName:vault.name,vaultKind:'shared',ownerFingerprint:ownerIdentity.fingerprint,ownerIsSelf:true});
    }
    // Use the actual extension-origin comparison-code protocol. The test owns
    // these disposable accounts; no production grant or approval is bypassed.
    const proof='DisposableConnectionProof'.repeat(3);
    const start=await worker.evaluate(async({origin,proof})=>{
      const response=await fetch(origin+'/api/companion/connect/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proof,scope:'access'})});
      if(!response.ok)throw new Error('Fixture workflow connection start failed');return response.json();
    },{origin,proof});
    await post(owner,`/extension-connect/${start.id}/approve`,{confirmed_code:start.code,workspace_id:own.workspace});
    const access=await worker.evaluate(async({origin,proof,id})=>{
      const request=path=>fetch(origin+'/api/companion/connect/'+id+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({proof,scope:'access'})});
      const response=await request('/poll');if(!response.ok)throw new Error('Fixture workflow connection poll failed');
      const result=await response.json();if(result.status!=='approved')throw new Error('Fixture connection not approved');
      await request('/ack');return {origin,token:result.token,kind:'access'};
    },{origin,proof,id:start.id});
    await worker.evaluate(({access,connection,connections})=>chrome.storage.local.set({accessConnection:access,connection,connections}),{access,connection:ownerConnections[0],connections:ownerConnections});
    const workflowMutations=[];
    companion.context.on('request',request=>{const path=new URL(request.url()).pathname;if(request.method()==='POST'&&/^\/api\/companion\/access\/workflows\//.test(path))workflowMutations.push(path);});
    const operator=await companion.context.newPage();
    await operator.goto(`chrome-extension://${new URL(worker.url()).host}/popup.html`);
    const home=operator.getByRole('region',{name:'Client access workflows'});
    await home.getByRole('combobox',{name:'Client',exact:true}).selectOption(client.id);
    await home.getByRole('combobox',{name:'Person',exact:true}).selectOption(other.id);
    await home.getByLabel('Preview only; make no changes').uncheck();
    await home.getByRole('button',{name:'Prepare offboarding plan',exact:true}).click();
    await expect(home.getByRole('heading',{name:'Review and approve',exact:true})).toBeVisible();
    const plan=(await get(owner,'/access-workflows')).workflows[0];
    await home.getByLabel('Current account password',{exact:true}).fill(password);
    await home.getByLabel('Unused MFA or recovery code',{exact:true}).fill(factors.recovery_codes[0]);
    await home.getByLabel('I approve this exact access removal plan.').check();
    await home.getByRole('button',{name:'Approve plan',exact:true}).click();
    const status=async()=>(await get(owner,'/access-workflows')).workflows.find(run=>run.id===plan.id).status;
    await expect.poll(status,{timeout:30000}).toBe('waiting_unlock');
    await operator.close();
    await worker.evaluate(connection=>chrome.storage.local.set({connection,connections:[connection]}),companion.connections[1]);
    const revokedPopup=await companion.context.newPage();
    await revokedPopup.goto(`chrome-extension://${new URL(worker.url()).host}/popup.html`);
    await revokedPopup.getByLabel('Sharing passphrase',{exact:true}).fill(master);
    await revokedPopup.getByLabel('Verified owner fingerprint',{exact:true}).fill(ownerIdentity.fingerprint);
    await revokedPopup.getByRole('button',{name:'Unlock',exact:true}).click();
    await expect(revokedPopup.getByRole('heading',{name:'Reconnect your vault',exact:true})).toBeVisible();
    await expect(revokedPopup.getByText('Unlocked · this popup only',{exact:true})).toHaveCount(0);
    await revokedPopup.close();
    for(const {id,name} of vaults){
      expect((await member.request.get(origin+'/api/team-vaults/'+id)).status()).toBe(404);
      const connection=companion.connections.find(item=>item.vaultId===id);
      expect((await companion.context.request.get(origin+'/api/companion/vault',{headers:{Authorization:'Bearer '+connection.token}})).status()).toBe(401);
      const ownerConnection=ownerConnections.find(item=>item.vaultId===id);
      const rotationPopup=await openCompanion(companion,ownerConnection,ownerConnections,ownerIdentity.fingerprint);
      await expect(rotationPopup.getByText('Approved vault key rotation finished automatically. The server will verify the removal.',{exact:true})).toBeVisible();
      await rotationPopup.close();
      const team=await get(owner,'/team-vaults/'+id);expect(team.epoch).toBe(2);
      const denied=await cache.evaluate(async({id,payload})=>{
        const handle=window.acceptanceCachedHandles[id];let rejected=0;
        for(const value of [payload,{...payload,epoch:1}]){try{await handle.decrypt(value);}catch{rejected++;}}
        // Bypass client epoch guards and use the correct new AAD: rejection
        // must come from AES-GCM with the retained old key itself.
        const bytes=value=>Uint8Array.from(atob(value),c=>c.charCodeAt(0));
        try{await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(payload.iv),additionalData:new TextEncoder().encode(`SentinelOps team vault v1:${id}:${payload.epoch}`)},window.acceptanceCachedKeys[id],bytes(payload.ciphertext));}catch{rejected++;}
        return rejected;
      },{id,payload:team.payload});expect(denied).toBe(3);
      await ownerPage.reload();await ownerPage.getByRole('button',{name:'Shared workspace vaults',exact:true}).click();await unlock(ownerPage);
      await ownerPage.getByRole('button',{name:name+' · owner',exact:true}).click();
      await ownerPage.getByRole('button',{name:'Verify and open shared vault',exact:true}).click();
      await expect(ownerPage.locator('article.entry-card').getByText('Disposable credential '+(vaults.findIndex(v=>v.id===id)+1),{exact:true})).toBeVisible();
    }
    await expect.poll(status,{timeout:45000}).toBe('complete');
    const report=await get(owner,`/access-workflows/${plan.id}/report`);
    expect(report.audit.valid).toBe(true);
    expect(JSON.stringify(report)).not.toContain(master);
    expect(JSON.stringify(report)).not.toContain('Disposable-before-removal');
    expect(own.workspace).toBe(other.workspace);
    expect(workflowMutations.filter(path=>path.endsWith('/approve'))).toHaveLength(1);
    expect(workflowMutations.filter(path=>path.endsWith('/rotation'))).toHaveLength(2);
    const reporting=await companion.context.newPage();
    await reporting.goto(`chrome-extension://${new URL(worker.url()).host}/popup.html`);
    const agency=reporting.getByRole('region',{name:'Client access workflows'});
    await agency.getByLabel('What needs doing?',{exact:true}).selectOption('proof');
    await agency.getByLabel('Report client',{exact:true}).selectOption(client.id);
    await agency.getByLabel('Agency / report brand',{exact:true}).fill('Disposable agency proof');
    await agency.getByRole('button',{name:'Preview exact snapshot',exact:true}).click();
    await expect(agency.getByRole('heading',{name:'Review before generation',exact:true})).toBeVisible();
    await agency.getByLabel('Current account password',{exact:true}).fill(password);
    await agency.getByLabel('Unused MFA or recovery code',{exact:true}).fill(factors.recovery_codes[3]);
    await agency.getByLabel('I reviewed this exact client metadata and selected associations. Generate a private, immutable report; nothing is shared yet.',{exact:true}).check();
    await agency.getByRole('button',{name:'Generate private Proof Pack',exact:true}).click();
    await expect(agency.getByText('Immutable Proof Pack generated. It is private until you separately approve a share link.',{exact:true})).toBeVisible();
    const downloaded=reporting.waitForEvent('download');
    await agency.getByRole('button',{name:'Download client PDF',exact:true}).click();
    const pdf=readFileSync(await (await downloaded).path());
    expect(pdf.subarray(0,5).toString()).toBe('%PDF-');
    expect(pdf.length).toBeGreaterThan(1000);
    await reporting.close();
    // Inspect both database and journal/WAL files in the fresh installation,
    // not just the API response, for these known disposable plaintexts.
    let inspected=0;
    for(const file of readdirSync(process.env.SENTINELOPS_E2E_DATA,{withFileTypes:true})){
      if(!file.isFile())continue;
      const bytes=readFileSync(join(process.env.SENTINELOPS_E2E_DATA,file.name));inspected++;
      for(const secret of [password,master,'Disposable-before-removal!1','Disposable-before-removal!2','Disposable-companion-secret!1','Disposable-companion-secret!2','JBSWY3DPEHPK3PXP'])expect(bytes.includes(Buffer.from(secret)),'Fixture plaintext must be absent from '+file.name).toBe(false);
    }
    expect(inspected).toBeGreaterThan(0);
  }catch(error){
    for(const context of [owner,member,...(companion?[companion.context]:[])])for(const page of context.pages()){
      if(!page.isClosed())console.error('Disposable fixture UI alerts:',await page.getByRole('alert').allTextContents().catch(()=>[]));
    }
    throw error;
  }finally{await Promise.allSettled([member.close(),owner.close(),companion?.context.close()]);}
});
