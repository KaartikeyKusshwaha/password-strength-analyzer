import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import VaultCollection from './VaultCollection';

it('creates a vault with per-vault browser policy and lock settings without sending a master passphrase',async()=>{
  const fetcher=vi.fn(async(url,options)=>({ok:true,json:async()=>url==='/api/vaults' && !options?.body?{vaults:[]}:url==='/api/vaults'?{...JSON.parse(options.body),id:'a'.repeat(24)}:{revision:0,envelope:null}}));
  vi.stubGlobal('fetch',fetcher);
  render(<VaultCollection/>);
  fireEvent.click(screen.getByRole('button',{name:'New vault'}));
  fireEvent.change(screen.getByLabelText('Vault name'),{target:{value:'Client Alpha'}});
  fireEvent.change(screen.getByLabelText('Purpose'),{target:{value:'project'}});
  fireEvent.change(screen.getByLabelText('Lock after inactivity'),{target:{value:'60'}});
  fireEvent.click(screen.getByLabelText('Allow browser connections to this vault'));
  fireEvent.click(screen.getByRole('button',{name:'Create vault space'}));
  await screen.findByRole('button',{name:'Create my vault'});
  const call=fetcher.mock.calls.find(([url,options])=>url==='/api/vaults' && options?.body);
  expect(JSON.parse(call[1].body)).toMatchObject({name:'Client Alpha',purpose:'project',lock_seconds:60,browser_enabled:false});
  expect(call[1].body).not.toContain('master');expect(call[1].body).not.toContain('password');
});
