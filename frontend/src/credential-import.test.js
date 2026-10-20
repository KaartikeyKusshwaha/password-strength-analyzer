import { expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { importCredentials, parseCsv } from './credential-import';
vi.stubGlobal('crypto',webcrypto);
it('imports supported vendor login formats locally and preserves quoted commas, quotes and newlines',()=>{
  const samples=[
    ['Chrome / compatible','name,url,username,password\r\n"My, site",https://example.test/login,fixture,"p,a""ss\nword"'],
    ['Bitwarden','type,name,login_uri,login_username,login_password,login_totp\nlogin,Site,https://example.test,fixture,secret,JBSWY3DPEHPK3PXP'],
    ['1Password','title,url,username,password,notes\nSite,https://example.test,fixture,secret,"Private note"'],
    ['LastPass','url,username,password,extra,name,grouping,fav\nhttps://example.test,fixture,secret,,Site,Personal,0'],
  ];
  for(const [format,csv] of samples){const result=importCredentials(csv);expect(result.format).toBe(format);expect(result.entries[0]).toMatchObject({type:'login',origin:'https://example.test',username:'fixture'});expect(JSON.stringify(result.skipped)).not.toContain('secret');}
  expect(importCredentials(samples[0][1]).entries[0].password).toBe('p,a"ss\nword');
  expect(importCredentials(samples[1][1]).entries[1].type).toBe('totp');
});
it('rejects malformed and unsupported CSV and explains skipped insecure or non-login records',()=>{
  for(const text of ['name,url,password\n"unterminated','name,name\na,b','name,url,username,password\nsite,https://example.test,fixture','unknown\nvalue'])expect(()=>importCredentials(text)).toThrow();
  const result=importCredentials('type,name,login_uri,login_username,login_password\nlogin,Good,https://example.test,user,secret\nlogin,Bad,http://example.test,user,secret\nsecure note,Note,,,');
  expect(result.entries).toHaveLength(1);expect(result.skipped).toHaveLength(2);
  expect(result.skipped[1].reason).toBe('Non-login item type');
  expect(()=>parseCsv('a,b\n"quoted"oops,field')).toThrow('Malformed CSV');
});
it('keeps duplicate websites as independent entries with distinct ids',()=>{
  const result=importCredentials('name,url,username,password\nOne,https://example.test,a,secret-one\nTwo,https://example.test,b,secret-two');
  expect(result.entries[0].origin).toBe(result.entries[1].origin);
  expect(result.entries[0].id).not.toBe(result.entries[1].id);
});
