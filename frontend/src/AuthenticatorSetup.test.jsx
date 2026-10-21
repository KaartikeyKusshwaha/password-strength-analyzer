import React from 'react';
import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen,waitFor} from '@testing-library/react';
import AuthenticatorSetup from '../../companion/extension/AuthenticatorSetup';
afterEach(cleanup);
it('requires explicit save and clears the key before awaiting synchronization',async()=>{
  let complete;const session={addAuthenticator:vi.fn(()=>new Promise(resolve=>complete=resolve))},onUpdated=vi.fn();
  render(<AuthenticatorSetup session={session} active={{origin:'https://example.test'}} onUpdated={onUpdated}/>);
  expect(session.addAuthenticator).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('Authenticator account name'),{target:{value:'Fixture account'}});
  const setup=screen.getByLabelText('Setup key or TOTP URI');fireEvent.change(setup,{target:{value:'JBSWY3DPEHPK3PXP'}});
  fireEvent.click(screen.getByRole('button',{name:'Encrypt and add authenticator'}));
  expect(session.addAuthenticator).toHaveBeenCalledWith('Fixture account','JBSWY3DPEHPK3PXP','https://example.test');expect(setup).toHaveValue('');
  complete('entry');await waitFor(()=>expect(onUpdated).toHaveBeenCalled());
  expect(screen.getByRole('status')).toHaveTextContent('does not enable 2FA');
});
