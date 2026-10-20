import {beforeEach,expect,it,vi} from 'vitest';
import {fillLoginForm,inspectLoginForm} from '../../companion/extension/login-form';
import {isNewPassword} from '../../companion/extension/form-policy';
const origin='https://practice.expandtesting.com';
const entry={origin,username:'public-fixture',password:'public-test-only'};
beforeEach(()=>{
  document.body.innerHTML='<form action="https://practice.expandtesting.com/authenticate"><label>Username<input name="username"></label><label>Password<input type="password" name="password" id="password" autocomplete="new-password"></label><button type="submit">Login</button></form>';
  vi.spyOn(HTMLElement.prototype,'getClientRects').mockReturnValue([{width:100,height:20}]);
});
it('fills the observed single-field sign-in despite its misleading new-password hint, without submission',()=>{
  const form=document.querySelector('form'),password=document.getElementById('password');
  const submit=vi.fn(event=>event.preventDefault()),changed=vi.fn();
  form.addEventListener('submit',submit);form.addEventListener('input',changed);
  expect(isNewPassword(password,origin+'/login')).toBe(false);
  expect(fillLoginForm(document,origin+'/login',entry)).toEqual({ok:true});
  expect(password.value).toBe(entry.password);expect(form.elements.username.value).toBe(entry.username);
  expect(changed).toHaveBeenCalledTimes(2);expect(submit).not.toHaveBeenCalled();
});
it('preflights without reading or modifying values and refuses again if the form changes before filling',()=>{
  const field=document.getElementById('password');
  expect(inspectLoginForm(document,origin+'/login',origin)).toEqual({ok:true});
  expect(field.value).toBe('');expect(document.querySelector('input[name=username]').value).toBe('');
  document.querySelector('form').action='https://other.test/collect';
  expect(fillLoginForm(document,origin+'/login',entry)).toEqual({ok:false,reason:'form_action'});
  expect(field.value).toBe('');
});
it('retains signup/change/name/confirmation protections even with a Login button',()=>{
  const password=document.getElementById('password');
  for(const path of ['/register','/signup','/change-password','/reset-password']) {
    expect(isNewPassword(password,origin+path)).toBe(true);
    expect(fillLoginForm(document,origin+path,entry).ok).toBe(false);
  }
  password.name='new-password';expect(fillLoginForm(document,origin+'/login',entry).ok).toBe(false);
  password.name='confirmation';expect(fillLoginForm(document,origin+'/login',entry).ok).toBe(false);
  expect(password.value).toBe('');
});
it('does not reinterpret an ambiguous or hidden-button new-password form as sign-in',()=>{
  const form=document.querySelector('form'),button=form.querySelector('button');
  button.textContent='Create account';expect(fillLoginForm(document,origin+'/login',entry).ok).toBe(false);
  button.textContent='Login';button.getClientRects=()=>[];expect(fillLoginForm(document,origin+'/login',entry).ok).toBe(false);
  button.getClientRects=()=>[{width:100,height:20}];form.insertAdjacentHTML('beforeend','<input type="password" name="confirm">');
  expect(fillLoginForm(document,origin+'/login',entry).ok).toBe(false);
});
it('rejects HTTP, sibling/lookalike origins and cross-origin submit destinations without modifying fields',()=>{
  for(const page of ['http://practice.expandtesting.com/login','https://other.expandtesting.com/login','https://practice.expandtesting.com.evil.test/login'])expect(fillLoginForm(document,page,entry).ok).toBe(false);
  document.querySelector('form').action='https://other.test/collect';expect(fillLoginForm(document,origin+'/login',entry).ok).toBe(false);
  expect(document.getElementById('password').value).toBe('');
});
it('rejects disabled/read-only password fields and ambiguous editable usernames',()=>{
  const field=document.getElementById('password');
  field.disabled=true;expect(fillLoginForm(document,origin+'/login',entry).ok).toBe(false);
  field.disabled=false;field.readOnly=true;expect(fillLoginForm(document,origin+'/login',entry).ok).toBe(false);
  field.readOnly=false;document.querySelector('form').insertAdjacentHTML('beforeend','<input type="email" name="second">');
  expect(fillLoginForm(document,origin+'/login',entry).ok).toBe(false);expect(field.value).toBe('');
});
