import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen} from '@testing-library/react';
import {Popup} from '../../companion/extension/popup';

afterEach(()=>{cleanup();vi.unstubAllGlobals();});
it('replaces an invalid connection unlock form with a scoped re-pairing path without deleting other vaults',async()=>{
  const connection={origin:'http://127.0.0.1:8110',token:'fixture-only'};
  const saved={connection,connections:[connection]};
  const remove=vi.fn(async key=>{delete saved[key];});
  vi.stubGlobal('chrome',{storage:{local:{get:vi.fn(async()=>({...saved})),remove,set:vi.fn()}},runtime:{sendMessage:vi.fn(async()=>null)},tabs:{query:vi.fn(async()=>[])}});
  const fetcher=vi.fn(async()=>({status:401,ok:false}));vi.stubGlobal('fetch',fetcher);
  render(<Popup/>);
  await screen.findByLabelText('Master passphrase');
  expect(screen.getByRole('option',{name:'Vault name not verified · 127.0.0.1:8110'})).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Master passphrase'),{target:{value:'disposable-test-only'}});
  fireEvent.click(screen.getByRole('button',{name:'Unlock',exact:true}));
  await screen.findByRole('heading',{name:'Reconnect your vault'});
  expect(screen.queryByLabelText('Master passphrase')).not.toBeInTheDocument();
  expect(JSON.stringify(fetcher.mock.calls)).not.toContain('disposable-test-only');
  fireEvent.click(screen.getByRole('button',{name:'Enter a new pairing token'}));
  await screen.findByRole('heading',{name:'Pair your private vault'});
  expect(remove).toHaveBeenCalledWith('connection');
  expect(saved.connections).toEqual([connection]);
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});
