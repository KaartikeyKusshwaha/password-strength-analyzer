import {act,render,screen,fireEvent} from '@testing-library/react';
import {afterEach,beforeEach,expect,it,vi} from 'vitest';
const {lock,unlock,save}=vi.hoisted(()=>({lock:vi.fn(),unlock:vi.fn(async()=>{}),save:vi.fn(async()=>({saved:true}))}));
vi.mock('../../companion/extension/vault-session',()=>({SaveSession:class{lock=lock;unlock=unlock;save=save;policy={browser_save:true,name:'Test vault',lock_seconds:180};}}));
import {Frame} from '../../companion/extension/vault-frame';
afterEach(()=>vi.useRealTimers());
beforeEach(()=>vi.clearAllMocks());
async function start(expires){
  vi.useFakeTimers();
  const connection={origin:'http://127.0.0.1:8110',token:'test-only',vaultName:'Test vault'};
  vi.stubGlobal('chrome',{storage:{local:{get:vi.fn(async()=>({connection,connections:[connection]}))}},runtime:{sendMessage:vi.fn(async()=>({entry:{origin:'https://example.test',username:'disposable',password:'fixture-only',expires}}))}});
  await act(async()=>{render(<Frame/>);});
}
it('counts down the original capture deadline and removes unlock controls and captured identity at expiry',async()=>{
  await start(Date.now()+2000);
  expect(screen.getByText(/expires in 2s/)).toBeInTheDocument();
  await act(async()=>vi.advanceTimersByTime(1000));expect(screen.getByText(/expires in 1s/)).toBeInTheDocument();
  await act(async()=>vi.advanceTimersByTime(1000));
  expect(screen.getByRole('heading',{name:'Save request expired'})).toBeInTheDocument();
  expect(screen.queryByLabelText('Master passphrase')).not.toBeInTheDocument();
  expect(screen.queryByText('disposable',{exact:true})).not.toBeInTheDocument();
  expect(screen.queryByText('https://example.test',{exact:true})).not.toBeInTheDocument();
  expect(lock).toHaveBeenCalled();expect(save).not.toHaveBeenCalled();
});
it('locks an already-unlocked save window at capture expiry without offering a stale save',async()=>{
  await start(Date.now()+2000);
  fireEvent.change(screen.getByLabelText('Master passphrase'),{target:{value:'disposable-test-only'}});
  await act(async()=>fireEvent.submit(screen.getByLabelText('Master passphrase').closest('form')));
  expect(screen.getByRole('button',{name:'Encrypt and save login'})).toBeInTheDocument();
  await act(async()=>vi.advanceTimersByTime(2000));
  expect(screen.queryByRole('button',{name:'Encrypt and save login'})).not.toBeInTheDocument();
  expect(screen.getByRole('button',{name:'Close this window'})).toBeInTheDocument();
});
it('expires an already-old capture immediately rather than granting three fresh minutes on window opening',async()=>{
  await start(Date.now()-1);
  expect(screen.getByRole('heading',{name:'Save request expired'})).toBeInTheDocument();
  expect(screen.queryByLabelText('Master passphrase')).not.toBeInTheDocument();
});
