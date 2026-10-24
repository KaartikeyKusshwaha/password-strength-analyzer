import React from 'react';
import {expect,it,vi} from 'vitest';
import {fireEvent,render,screen,waitFor} from '@testing-library/react';
import AdminMfaEnrollment from './AdminMfaEnrollment';
import {api} from './api';
vi.mock('./api',()=>({api:vi.fn()}));
vi.mock('./SetupQr',()=>({default:()=>null}));
vi.mock('./VaultCollection',()=>({default:props=><p>{props.me?'Unexpected administrative vault surface':'Personal vault access only'}</p>}));

it('requires real setup and confirmation, clears setup material, and retains recovery codes until explicit continuation',async()=>{
  const onDone=vi.fn();api.mockImplementation(async path=>path==='/mfa/setup'?{secret:'fixture-private-setup',uri:'otpauth://fixture'}:{recovery_codes:['fixture-recovery-one']});
  render(<AdminMfaEnrollment onDone={onDone} onSignOut={vi.fn()}/>);
  const password=screen.getByLabelText('Current account password');fireEvent.change(password,{target:{value:'Fixture-only-password'}});
  fireEvent.submit(password.closest('form'));
  expect(password.value).toBe('');
  expect(await screen.findByLabelText('Private setup key')).toHaveValue('fixture-private-setup');
  const code=screen.getByLabelText('Authenticator code');fireEvent.change(code,{target:{value:'123456'}});fireEvent.submit(code.closest('form'));
  expect(await screen.findByLabelText('Private recovery codes')).toHaveValue('fixture-recovery-one');
  expect(screen.queryByLabelText('Private setup key')).not.toBeInTheDocument();expect(onDone).not.toHaveBeenCalled();
  const saved=screen.getByRole('checkbox');expect(saved).toBeRequired();fireEvent.click(saved);fireEvent.submit(saved.closest('form'));
  await waitFor(()=>expect(onDone).toHaveBeenCalledOnce());
  expect(api).toHaveBeenCalledWith('/mfa/enable',{code:'123456'});
});

it('keeps personal vaults available without shared administration and does not simulate failed enrollment',async()=>{
  api.mockRejectedValue(new Error('Invalid code or expired setup'));
  render(<AdminMfaEnrollment onDone={vi.fn()} onSignOut={vi.fn()}/>);
  fireEvent.click(screen.getByRole('button',{name:'Open personal vaults'}));
  expect(await screen.findByText('Personal vault access only')).toBeInTheDocument();
  const password=screen.getByLabelText('Current account password');fireEvent.change(password,{target:{value:'Fixture-only-password'}});fireEvent.submit(password.closest('form'));
  expect(await screen.findByRole('alert')).toHaveTextContent('Invalid code');
  expect(screen.queryByLabelText('Private recovery codes')).not.toBeInTheDocument();
});
