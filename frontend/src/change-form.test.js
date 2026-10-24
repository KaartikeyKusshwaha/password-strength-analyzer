import {expect,it,vi} from 'vitest';
import {preparePasswordChange} from '../../companion/extension/change-form';
const message={origin:'https://example.test',current:'old-fixture-password',replacement:'new-fixture-generated-password',username:'fixture'};
function form(action='https://example.test/change') {return `<form action="${action}"><input autocomplete="username" value="fixture"><input type="password" autocomplete="current-password"><input type="password" autocomplete="new-password"><input type="password" name="confirm_password"><button>Submit</button></form>`;}
it('prepares one explicit same-origin change form without submitting or clicking',()=>{
  document.body.innerHTML=form();const submit=vi.fn(e=>e.preventDefault());document.querySelector('form').addEventListener('submit',submit);const click=vi.fn();document.querySelector('button').addEventListener('click',click);
  expect(preparePasswordChange(document,'https://example.test/change',message,()=>true)).toEqual({ok:true,submitted:false});
  expect([...document.querySelectorAll('input[type=password]')].map(f=>f.value)).toEqual([message.current,message.replacement,message.replacement]);expect(submit).not.toHaveBeenCalled();expect(click).not.toHaveBeenCalled();
});
it('rejects cross-origin forms, lookalikes, multiple forms, account mismatch, hidden and ambiguous fields before writing secrets',()=>{
  for(const [html,url,visible] of [[form('https://evil.test/collect'),'https://example.test/change',()=>true],[form(),'https://example.test.evil.test/change',()=>true],[form()+form(),'https://example.test/change',()=>true],[form().replace('value="fixture"','value="other-account"'),'https://example.test/change',()=>true],[form(),'https://example.test/change',()=>false],[form().replace('</form>','<input type="password" name="ambiguous"></form>'),'https://example.test/change',()=>true]]){
    document.body.innerHTML=html;expect(preparePasswordChange(document,url,message,visible).ok).toBe(false);expect([...document.querySelectorAll('input[type=password]')].every(f=>!f.value)).toBe(true);
  }
});
it('leaves fields untouched when the generated password exceeds a site limit or violates its pattern',()=>{
  for(const rule of ['maxlength="16"','minlength="80"','pattern="[0-9]+"']) {
    document.body.innerHTML=form().replace('autocomplete="new-password"','autocomplete="new-password" '+rule);
    expect(preparePasswordChange(document,'https://example.test/change',message,()=>true).ok).toBe(false);
    expect([...document.querySelectorAll('input[type=password]')].every(field=>!field.value)).toBe(true);
  }
});
