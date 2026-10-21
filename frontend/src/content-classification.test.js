import {beforeEach,expect,it,vi} from 'vitest';
vi.mock('@zxcvbn-ts/core',()=>({ZxcvbnFactory:class {check(){return {score:2,feedback:{}};}}}));
vi.mock('@zxcvbn-ts/language-common',()=>({adjacencyGraphs:{},dictionary:{}}));
vi.mock('@zxcvbn-ts/language-en',()=>({translations:{},dictionary:{}}));
vi.mock('./lab',()=>({generatePassword:()=> 'public-generated-fixture'}));
let listeners,observerCallback,shadows;
beforeEach(async()=>{
  vi.resetModules();listeners=[];shadows=[];
  for(const element of [...document.documentElement.children])if(element.tagName==='DIV')element.remove();
  vi.stubGlobal('location',{href:'https://example.test/login',origin:'https://example.test'});
  vi.stubGlobal('chrome',{runtime:{id:'test-extension',onMessage:{addListener:vi.fn()}}});
  vi.stubGlobal('MutationObserver',class {constructor(callback){observerCallback=callback;}observe(){}});
  vi.spyOn(HTMLElement.prototype,'getClientRects').mockReturnValue([{width:100,height:20}]);
  const attach=HTMLElement.prototype.attachShadow;
  vi.spyOn(HTMLElement.prototype,'attachShadow').mockImplementation(function(options){const root=attach.call(this,options);shadows.push(root);return root;});
  const original=HTMLElement.prototype.addEventListener;
  vi.spyOn(HTMLElement.prototype,'addEventListener').mockImplementation(function(type,handler,...args){listeners.push({target:this,type,handler});return original.call(this,type,handler,...args);});
  document.body.innerHTML='<form action="https://example.test/authenticate"><input name="username"><input id="password" name="password" type="password" autocomplete="new-password"></form>';
  await import('../../companion/extension/content');
});
function focusPassword(){listeners.find(e=>e.target.id==='password' && e.type==='focus').handler({isTrusted:true});}
const panelCount=()=>[...document.documentElement.children].filter(e=>e.tagName==='DIV').length;
it('reclassifies on focus when a login submit button appears after initial attachment',()=>{
  document.querySelector('form').insertAdjacentHTML('beforeend','<button type="submit">Login</button>');
  focusPassword();expect(panelCount()).toBe(1);
  expect(shadows.at(-1).textContent).toContain('Choose saved login');
  expect(shadows.at(-1).textContent).not.toContain('Use a strong password');
});
it('attaches to fields that become new-password fields later and closes a stale suggestion after a form change',async()=>{
  // Initially incomplete new-password form: suggestions are available.
  focusPassword();expect(panelCount()).toBe(1);
  document.querySelector('form').insertAdjacentHTML('beforeend','<button type="submit">Login</button>');
  vi.useFakeTimers();observerCallback();await vi.advanceTimersByTimeAsync(250);
  expect(panelCount()).toBe(0);vi.useRealTimers();
  document.getElementById('password').name='new-password';
  focusPassword();expect(panelCount()).toBe(1);
});
it('reclassifies a field initially marked current-password when it later becomes a registration field',async()=>{
  const field=document.getElementById('password');field.autocomplete='current-password';
  listeners=[];vi.resetModules();await import('../../companion/extension/content');
  focusPassword();expect(panelCount()).toBe(1);
  expect(shadows.at(-1).textContent).toContain('Choose saved login');
  field.autocomplete='new-password';field.name='new-password';
  focusPassword();expect(panelCount()).toBe(1);
  expect(shadows.at(-1).textContent).toContain('Use a strong password');
});
