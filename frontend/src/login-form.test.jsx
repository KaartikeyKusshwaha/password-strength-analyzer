import {beforeEach,expect,it,vi} from 'vitest';
import {fillLoginForm,inspectLoginForm} from '../../companion/extension/login-form';
import {isNewPassword} from '../../companion/extension/form-policy';
import React,{useState} from 'react';
import {render,cleanup} from '@testing-library/react';
const origin='https://practice.expandtesting.com';
const entry={origin,username:'public-fixture',password:'public-test-only'};
beforeEach(()=>{
  document.body.innerHTML='<form action="https://practice.expandtesting.com/authenticate"><label>Username<input name="username"></label><label>Password<input type="password" name="password" id="password" autocomplete="new-password"></label><button type="submit">Login</button></form>';
  vi.spyOn(HTMLElement.prototype,'getClientRects').mockReturnValue([{width:100,height:20}]);
});
it('fills the observed single-field sign-in despite its misleading new-password hint, without submission',async()=>{
  const form=document.querySelector('form'),password=document.getElementById('password');
  const submit=vi.fn(event=>event.preventDefault()),changed=vi.fn();
  form.addEventListener('submit',submit);form.addEventListener('input',changed);
  expect(isNewPassword(password,origin+'/login')).toBe(false);
  expect(await fillLoginForm(document,origin+'/login',entry)).toEqual({ok:true,filled:'login'});
  expect(password.value).toBe(entry.password);expect(form.elements.username.value).toBe(entry.username);
  expect(changed).toHaveBeenCalledTimes(2);expect(submit).not.toHaveBeenCalled();
});
it('preflights without reading or modifying values and refuses again if the form changes before filling',async()=>{
  const field=document.getElementById('password');
  expect(inspectLoginForm(document,origin+'/login',origin)).toEqual({ok:true});
  expect(field.value).toBe('');expect(document.querySelector('input[name=username]').value).toBe('');
  document.querySelector('form').action='https://other.test/collect';
  expect(await fillLoginForm(document,origin+'/login',entry)).toEqual({ok:false,reason:'form_action'});
  expect(field.value).toBe('');
});
it('retains signup/change/name/confirmation protections even with a Login button',async()=>{
  const password=document.getElementById('password');
  for(const path of ['/register','/signup','/change-password','/reset-password']) {
    expect(isNewPassword(password,origin+path)).toBe(true);
    expect((await fillLoginForm(document,origin+path,entry)).ok).toBe(false);
  }
  password.name='new-password';expect((await fillLoginForm(document,origin+'/login',entry)).ok).toBe(false);
  password.name='confirmation';expect((await fillLoginForm(document,origin+'/login',entry)).ok).toBe(false);
  expect(password.value).toBe('');
});
it('does not reinterpret an ambiguous or hidden-button new-password form as sign-in',async()=>{
  const form=document.querySelector('form'),button=form.querySelector('button');
  button.textContent='Create account';expect((await fillLoginForm(document,origin+'/login',entry)).ok).toBe(false);
  button.textContent='Login';button.getClientRects=()=>[];expect((await fillLoginForm(document,origin+'/login',entry)).ok).toBe(false);
  button.getClientRects=()=>[{width:100,height:20}];form.insertAdjacentHTML('beforeend','<input type="password" name="confirm">');
  expect((await fillLoginForm(document,origin+'/login',entry)).ok).toBe(false);
});
it('rejects HTTP, sibling/lookalike origins and cross-origin submit destinations without modifying fields',async()=>{
  for(const page of ['http://practice.expandtesting.com/login','https://other.expandtesting.com/login','https://practice.expandtesting.com.evil.test/login'])expect((await fillLoginForm(document,page,entry)).ok).toBe(false);
  document.querySelector('form').action='https://other.test/collect';expect((await fillLoginForm(document,origin+'/login',entry)).ok).toBe(false);
  expect(document.getElementById('password').value).toBe('');
});
it('rejects disabled/read-only password fields and ambiguous editable usernames',async()=>{
  const field=document.getElementById('password');
  field.disabled=true;expect((await fillLoginForm(document,origin+'/login',entry)).ok).toBe(false);
  field.disabled=false;field.readOnly=true;expect((await fillLoginForm(document,origin+'/login',entry)).ok).toBe(false);
  field.readOnly=false;document.querySelector('form').insertAdjacentHTML('beforeend','<input type="email" name="second">');
  expect((await fillLoginForm(document,origin+'/login',entry)).ok).toBe(false);expect(field.value).toBe('');
});
it('does not write a password after a username handler changes the form destination',async()=>{
  const form=document.querySelector('form'),password=document.getElementById('password');
  form.elements.username.addEventListener('input',()=>{form.action='https://other.test/collect';});
  expect(await fillLoginForm(document,origin+'/login',entry)).toEqual({ok:false,reason:'form_changed'});
  expect(password.value).toBe('');
});
it('does not follow replacement password fields created by an input handler',async()=>{
  const form=document.querySelector('form'),original=document.getElementById('password');
  form.elements.username.addEventListener('input',()=>{original.replaceWith(original.cloneNode());});
  expect(await fillLoginForm(document,origin+'/login',entry)).toEqual({ok:false,reason:'form_changed'});
  expect(original.value).toBe('');expect(document.getElementById('password').value).toBe('');
});
it('reports a website value reset without silently retrying or submitting',async()=>{
  const password=document.getElementById('password'),events=vi.fn(),submit=vi.fn();
  password.addEventListener('input',()=>{events();queueMicrotask(()=>{password.value='';});});
  document.querySelector('form').addEventListener('submit',submit);
  expect(await fillLoginForm(document,origin+'/login',entry)).toEqual({ok:false,reason:'value_rejected'});
  expect(events).toHaveBeenCalledTimes(1);expect(submit).not.toHaveBeenCalled();
});
it('distinguishes a password-only step without claiming that a username was filled',async()=>{
  document.body.innerHTML='<form action="https://practice.expandtesting.com/authenticate"><input type="password" autocomplete="current-password"><button>Sign in</button></form>';
  expect(await fillLoginForm(document,origin+'/login',entry)).toEqual({ok:true,filled:'password'});
});
it('fills React controlled inputs through their normal input events and retains both values',async()=>{
  document.body.innerHTML='';const submit=vi.fn(event=>event.preventDefault());
  function ControlledLogin(){
    const [values,setValues]=useState({username:'',password:''});
    const update=event=>{const {name,value}=event.target;setValues(previous=>({...previous,[name]:value}));};
    return <form action={origin+'/authenticate'} onSubmit={submit}><input name="username" autoComplete="username" value={values.username} onChange={update}/><input name="password" type="password" autoComplete="current-password" value={values.password} onChange={update}/><button type="submit">Sign in</button></form>;
  }
  render(<ControlledLogin/>);
  expect(await fillLoginForm(document,origin+'/login',entry)).toEqual({ok:true,filled:'login'});
  expect(document.querySelector('input[name=username]')).toHaveValue(entry.username);
  expect(document.querySelector('input[name=password]')).toHaveValue(entry.password);
  expect(submit).not.toHaveBeenCalled();cleanup();
});
