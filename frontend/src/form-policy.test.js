import { expect, it } from 'vitest';
import { isNewPassword, formOriginAllowed, setPasswordFields } from '../../companion/extension/form-policy';
import { accountHealth, changePasswordUrl } from './account-health';

it('detects signup/change fields without treating known current or confirm fields as new passwords', () => {
  document.body.innerHTML='<form><input id="password" type="password"><input id="confirm" type="password"><input id="old" type="password" autocomplete="current-password"></form>';
  expect(isNewPassword(document.getElementById('password'),'https://example.test/register')).toBe(true);
  expect(isNewPassword(document.getElementById('confirm'),'https://example.test/register')).toBe(false);
  expect(isNewPassword(document.getElementById('old'),'https://example.test/reset-password')).toBe(false);
  expect(isNewPassword(document.getElementById('password'),'https://example.test/login')).toBe(false);
});
it('generated passwords fill confirmation in the same form and leave existing passwords alone', () => {
  document.body.innerHTML='<form><input id="old" type="password" autocomplete="current-password" value="old"><input id="new-password" type="password"><input id="confirm" type="password"></form><form><input id="unrelated-confirm" type="password"></form>';
  setPasswordFields(document.getElementById('new-password'),'fixture-generated');
  expect(document.getElementById('new-password').value).toBe('fixture-generated');
  expect(document.getElementById('confirm').value).toBe('fixture-generated');
  expect(document.getElementById('old').value).toBe('old');
  expect(document.getElementById('unrelated-confirm').value).toBe('');
});
it('rejects insecure pages or cross-origin form submission targets', () => {
  expect(formOriginAllowed('https://example.test/register','/register')).toBe(true);
  expect(formOriginAllowed('http://example.test/register','/register')).toBe(false);
  expect(formOriginAllowed('https://example.test/register','https://evil.test/collect')).toBe(false);
  expect(formOriginAllowed('https://example.test/register','javascript:alert(1)')).toBe(false);
});
it('account review excludes TOTP secrets and identifies local reuse without network requests', () => {
  const entries=[{id:'a',type:'login',password:'weak'},{id:'b',type:'login',password:'weak'},{id:'c',type:'login',password:'strong-fixture-value'},{id:'d',type:'totp',secret:'SECRET'}];
  const result=accountHealth(entries, password=>({score:password==='weak'?1:4}));
  expect(result).toEqual([{id:'a',weak:true,reused:true,assessed:true},{id:'b',weak:true,reused:true,assessed:true},{id:'c',weak:false,reused:false,assessed:true}]);
  expect(JSON.stringify(result)).not.toContain('SECRET');
  expect(changePasswordUrl('https://example.test')).toBe('https://example.test/.well-known/change-password');
  expect(()=>changePasswordUrl('http://evil.test')).toThrow();
});
