import {beforeEach,expect,it,vi} from 'vitest';
import {fireEvent,render,screen,waitFor} from '@testing-library/react';
import Passkeys from './Passkeys';
import {Auth} from './App';
import {api} from './api';
import {performPasskey} from './passkey-client';
vi.mock('./api',()=>({api:vi.fn()}));
vi.mock('./passkey-client',()=>({supportedPasskeys:()=>true,performPasskey:vi.fn()}));
beforeEach(()=>{vi.mocked(api).mockReset();vi.mocked(performPasskey).mockReset();});
it('shows an unsupported-origin state without offering enrollment or changing any origin',async()=>{
  vi.mocked(api).mockResolvedValue({available:false,credentials:[]});render(<Passkeys mfaEnabled={false}/>);
  await screen.findByText(/This origin is unsupported/);
  expect(screen.queryByRole('button',{name:'Create account passkey'})).not.toBeInTheDocument();
  expect(performPasskey).not.toHaveBeenCalled();expect(api).toHaveBeenCalledWith('/passkeys');
});
it('reauthenticates explicit removal and refreshes the rotated session and credential list',async()=>{
  const item={id:'a'.repeat(24),label:'Work laptop',created_at:1000,last_used:null};let removed=false;
  vi.mocked(api).mockImplementation(async path=>{if(path.endsWith('/remove')){removed=true;return {csrf:'new-fixture'};}return {available:true,credentials:removed?[]:[item]};});
  const refreshed=vi.fn(async()=>{});render(<Passkeys mfaEnabled onSessionChanged={refreshed}/>);
  fireEvent.click(await screen.findByRole('button',{name:'Remove Work laptop'}));
  fireEvent.change(screen.getByLabelText('Current account password'),{target:{value:'public-test-password'}});
  fireEvent.change(screen.getByLabelText('Unused authenticator or recovery code'),{target:{value:'public-test-code'}});
  fireEvent.click(screen.getByRole('button',{name:'Remove this passkey'}));
  await screen.findByText('No passkeys enrolled.');
  expect(api).toHaveBeenCalledWith('/passkeys/'+item.id+'/remove',{password:'public-test-password',code:'public-test-code'});
  expect(refreshed).toHaveBeenCalledTimes(1);expect(performPasskey).not.toHaveBeenCalled();
});
it('enrolls only after a user form submission and clears the reauthentication inputs',async()=>{
  vi.mocked(api).mockResolvedValue({available:true,credentials:[]});vi.mocked(performPasskey).mockResolvedValue({id:'fixture'});
  render(<Passkeys mfaEnabled={false}/>);await screen.findByRole('button',{name:'Create account passkey'});
  expect(performPasskey).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('Passkey name'),{target:{value:'Laptop'}});
  fireEvent.change(screen.getByLabelText('Current account password'),{target:{value:'public-test-password'}});
  fireEvent.click(screen.getByRole('button',{name:'Create account passkey'}));
  await screen.findByText('Passkey enrolled for this SentinelOps account.');
  expect(performPasskey).toHaveBeenCalledWith('register',expect.objectContaining({label:'Laptop',password:'public-test-password',signal:expect.any(AbortSignal)}));
  expect(screen.getByLabelText('Current account password')).toHaveValue('');
});
it('passkey sign-in uses the email without reading/sending the password and preserves the MFA screen',async()=>{
  vi.mocked(api).mockImplementation(async path=>path==='/passkeys/status'?{available:true}:{mfa_required:false});
  vi.mocked(performPasskey).mockResolvedValue({mfa_required:true,csrf:'fixture'});
  const done=vi.fn();render(<Auth setup={false} onDone={done}/>);
  fireEvent.change(screen.getByLabelText('Email address'),{target:{value:'fixture@example.test'}});
  await waitFor(()=>expect(screen.getByRole('button',{name:'Sign in with a passkey'})).toBeEnabled());
  fireEvent.click(screen.getByRole('button',{name:'Sign in with a passkey'}));
  await screen.findByRole('heading',{name:'One more check'});
  expect(done).not.toHaveBeenCalled();expect(performPasskey).toHaveBeenCalledWith('login',expect.objectContaining({email:'fixture@example.test'}));
  expect(vi.mocked(performPasskey).mock.calls[0][1]).not.toHaveProperty('password');
  fireEvent.change(screen.getByLabelText('Authenticator or recovery code'),{target:{value:'public-fixture-code'}});
  fireEvent.click(screen.getByRole('button',{name:'Verify and continue'}));
  await waitFor(()=>expect(done).toHaveBeenCalledTimes(1));expect(api).toHaveBeenCalledWith('/login/factor',{code:'public-fixture-code'});
});
it('explains a pending device prompt, freezes the account fields and restores sign-in after cancellation',async()=>{
  vi.mocked(api).mockResolvedValue({available:true});
  vi.mocked(performPasskey).mockImplementation((mode,{signal,onPhase})=>{
    onPhase('authenticator');
    return new Promise((_,reject)=>signal.addEventListener('abort',()=>reject(new Error('Passkey request cancelled or not approved.')),{once:true}));
  });
  const done=vi.fn();render(<Auth setup={false} onDone={done}/>);
  fireEvent.change(screen.getByLabelText('Email address'),{target:{value:'fixture@example.test'}});
  await waitFor(()=>expect(screen.getByRole('button',{name:'Sign in with a passkey'})).toBeEnabled());
  fireEvent.click(screen.getByRole('button',{name:'Sign in with a passkey'}));
  expect(await screen.findByRole('status')).toHaveTextContent('Complete the Windows or browser passkey prompt');
  expect(screen.getByLabelText('Email address')).toBeDisabled();expect(screen.getByLabelText('Password')).toBeDisabled();
  fireEvent.click(screen.getByRole('button',{name:'Cancel passkey request'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('cancelled');
  expect(screen.getByRole('button',{name:'Sign in'})).toBeEnabled();expect(done).not.toHaveBeenCalled();
});
