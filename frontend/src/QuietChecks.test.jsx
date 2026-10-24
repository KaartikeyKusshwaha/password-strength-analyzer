import React from 'react';
import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen,waitFor} from '@testing-library/react';
import QuietChecks from '../../companion/extension/QuietChecks';
afterEach(cleanup);
const scope={origin:'https://example.test',https:true,permission:'https://example.test/*'};
it('requests exact-origin access only on an explicit enable click',async()=>{
  const browser={permissions:{request:vi.fn(async()=>false)},runtime:{sendMessage:vi.fn(async()=>({ok:true,sites:[]}))}};
  render(<QuietChecks browser={browser} scope={scope}/>);expect(browser.permissions.request).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button',{name:'Enable quiet checks for this site'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('declined');
  expect(browser.permissions.request).toHaveBeenCalledWith({origins:['https://example.test/*']});
  expect(browser.runtime.sendMessage.mock.calls.every(([message])=>message.type==='site-monitor-status')).toBe(true);
});
