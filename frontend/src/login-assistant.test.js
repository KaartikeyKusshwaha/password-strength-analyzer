import {beforeEach,afterEach,expect,it,vi} from 'vitest';
import {offerLogin} from '../../companion/extension/login-assistant';
import {readFileSync} from 'node:fs';
const background=readFileSync('../companion/extension/public/background.js','utf8');
beforeEach(()=>{
  document.body.innerHTML='<form action="https://accounts.example.test/session"><input name="username"><input type="password" autocomplete="current-password"></form>';
  vi.spyOn(HTMLElement.prototype,'getClientRects').mockReturnValue([{width:100,height:20}]);
});
afterEach(()=>vi.restoreAllMocks());
it('offers an extension-owned login choice without reading credentials or sending messages',()=>{
  const field=document.querySelector('[type=password]'),browser={runtime:{sendMessage:vi.fn()}};
  Object.defineProperty(field,'value',{get(){throw new Error('Password read');}});
  const host=offerLogin(document,'https://accounts.example.test/login',field,browser);
  expect(host).not.toBeNull();expect(host.shadowRoot).toBeNull();
  expect(browser.runtime.sendMessage).not.toHaveBeenCalled();
});
it('does not offer login assistance for frames, cross-origin forms or signup fields',()=>{
  const field=document.querySelector('[type=password]');
  expect(offerLogin(document,'https://accounts.example.test/login',field,{}, {isTop:false})).toBeNull();
  document.querySelector('form').action='https://other.example/session';
  expect(offerLogin(document,'https://accounts.example.test/login',field,{})).toBeNull();
  document.querySelector('form').action='https://accounts.example.test/session';field.autocomplete='new-password';field.name='new_password';
  expect(offerLogin(document,'https://accounts.example.test/signup',field,{})).toBeNull();
});
function worker(tab){
  let listener;
  const chrome={runtime:{id:'fixture',getURL:path=>'chrome-extension://fixture/'+path,onMessage:{addListener:fn=>listener=fn}},windows:{onRemoved:{addListener:vi.fn()}},tabs:{get:vi.fn(async()=>tab)},action:{openPopup:vi.fn(async()=>{})}};
  new Function('chrome',background)(chrome);
  return {chrome,listener};
}
it('opens the companion only for the active sender origin and never returns vault contents',async()=>{
  const {chrome,listener}=worker({active:true,url:'https://accounts.example.test/login',windowId:7});
  const reply=vi.fn();
  listener({type:'open-login-companion'},{id:'fixture',frameId:0,url:'https://accounts.example.test/login',tab:{id:1,windowId:7}},reply);
  await vi.waitFor(()=>expect(reply).toHaveBeenCalledWith({ok:true}));
  expect(chrome.action.openPopup).toHaveBeenCalledWith({windowId:7});
});
it('rejects stale-origin and frame requests without opening the popup',async()=>{
  const {chrome,listener}=worker({active:true,url:'https://other.example/',windowId:7});const reply=vi.fn();
  listener({type:'open-login-companion'},{id:'fixture',frameId:0,url:'https://accounts.example.test/',tab:{id:1,windowId:7}},reply);
  await vi.waitFor(()=>expect(reply).toHaveBeenCalledWith({ok:false}));
  listener({type:'open-login-companion'},{id:'fixture',frameId:1,url:'https://accounts.example.test/',tab:{id:1,windowId:7}},reply);
  expect(chrome.action.openPopup).not.toHaveBeenCalled();
});
