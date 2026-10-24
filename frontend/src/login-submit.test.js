import {afterEach,expect,it,vi} from 'vitest';
import {loginSubmission} from '../../companion/extension/login-submit';
afterEach(()=>{document.body.innerHTML='';vi.restoreAllMocks();});
function form(extra=''){
  document.body.innerHTML=`<form method="post" action="https://fixture.test/login"><input autocomplete="username" value="public-user"><input name="password" type="password" autocomplete="current-password" value="public-fixture">${extra}</form>`;
  vi.spyOn(HTMLElement.prototype,'getClientRects').mockReturnValue([{}]);return document.querySelector('form');
}
it('extracts only a bounded standard same-origin HTTPS login',()=>{
  expect(loginSubmission(form(),'https://fixture.test/login')).toEqual({origin:'https://fixture.test',username:'public-user',password:'public-fixture'});
});
it('rejects signup, confirmation, insecure destinations and GET forms',()=>{
  let f=form();f.querySelector('[type=password]').autocomplete='new-password';f.querySelector('[type=password]').name='newPassword';
  expect(loginSubmission(f,'https://fixture.test/register')).toBeNull();
  expect(loginSubmission(form('<input type="password" name="confirmation">'),'https://fixture.test/login')).toBeNull();
  f=form();f.action='https://other.test/login';expect(loginSubmission(f,'https://fixture.test/login')).toBeNull();
  f=form();f.method='get';expect(loginSubmission(f,'https://fixture.test/login')).toBeNull();
  expect(loginSubmission(form(),'http://fixture.test/login')).toBeNull();
});
