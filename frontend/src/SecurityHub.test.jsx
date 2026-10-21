import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import {expect,it,vi} from 'vitest';
import SecurityHub,{toolUrl} from '../../companion/extension/security-hub';
it('opens each integrated feature in the same service without passing tokens, credentials or page URLs',async()=>{
  const browser={tabs:{create:vi.fn(async()=>{})}};
  render(<SecurityHub browser={browser} origin="http://127.0.0.1:8110"/>);
  for(const name of ['Passwords & vaults','Two-factor authentication','Vulnerability checks'])fireEvent.click(screen.getByRole('button',{name,exact:true}));
  await waitFor(()=>expect(browser.tabs.create).toHaveBeenCalledTimes(3));
  expect(browser.tabs.create.mock.calls.map(([args])=>args.url)).toEqual(['passwords','authenticator','vulnerabilities'].map(tool=>'http://127.0.0.1:8110/#tool='+tool));
});
it('rejects removed or unknown tools and unsafe destination schemes',()=>{
  expect(()=>toolUrl('https://example.test','phishing')).toThrow();
  expect(()=>toolUrl('javascript:alert(1)','passwords')).toThrow();
  expect(()=>toolUrl('https://example.test/path','passwords')).toThrow();
  expect(()=>toolUrl('https://example.test','unrecognized')).toThrow();
});
