import {expect,it,vi} from 'vitest';
import {credentialCsv,downloadCredentialCsv,exportableLogins} from './credential-export';
import {importCredentials} from './credential-import';

const login={id:'login',type:'login',title:'Quoted "client", account\nsecond line',origin:'https://example.com',username:'=formula,user',password:'+exact"password,\nvalue',pending_change:{password:'not-confirmed'},notes:'private note',history:[{password:'old-secret'}]};
const archived={...login,id:'archived',title:'Archived account',history:{version:1,events:[],archived_at:'2026-10-21T00:00:00.000Z'}};

it('round trips exact credential values without exporting staged secrets or other item types',()=>{
  const csv=credentialCsv([login,{id:'totp',type:'totp',secret:'PRIVATEAUTHKEY'},archived]);
  const restored=importCredentials(csv);
  expect(restored.entries).toHaveLength(1);
  expect(restored.entries[0]).toMatchObject({title:login.title,origin:login.origin,username:login.username,password:login.password});
  expect(csv).not.toContain('not-confirmed');expect(csv).not.toContain('PRIVATEAUTHKEY');expect(csv).not.toContain('private note');expect(csv).not.toContain('old-secret');
});

it('includes archived logins only when selected and rejects an empty export',()=>{
  expect(exportableLogins([login,archived])).toHaveLength(1);
  expect(importCredentials(credentialCsv([login,archived],true)).entries).toHaveLength(2);
  expect(()=>credentialCsv([archived])).toThrow('No login entries');
});

it('preserves Unicode and independent duplicate origins without merging accounts',()=>{
  const first={...login,title:'ग्राहक 🔐',username:'user@example.com',password:'exact-é-密碼'},second={...first,id:'other',password:'other-disposable'};
  const {entries}=importCredentials(credentialCsv([first,second]));
  expect(entries).toHaveLength(2);expect(entries.map(entry=>entry.password)).toEqual([first.password,second.password]);
  expect(entries[0].title).toBe(first.title);
});

it('creates the plaintext file locally and releases the object URL',async()=>{
  vi.useFakeTimers();
  const create=vi.fn(()=> 'blob:private-export'),revoke=vi.fn(),click=vi.spyOn(HTMLAnchorElement.prototype,'click').mockImplementation(()=>{});
  vi.stubGlobal('URL',Object.assign(URL,{createObjectURL:create,revokeObjectURL:revoke}));
  try{
    downloadCredentialCsv([login]);
    expect(create).toHaveBeenCalledOnce();expect(create.mock.calls[0][0].type).toBe('text/csv;charset=utf-8');
    expect(click.mock.instances[0].download).toBe('sentinelops-logins.csv');
    vi.runAllTimers();expect(revoke).toHaveBeenCalledWith('blob:private-export');
  }finally{vi.useRealTimers();}
});
