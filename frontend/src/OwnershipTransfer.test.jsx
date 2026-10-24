import {act,fireEvent,render,screen,waitFor} from '@testing-library/react';
import {expect,it,vi} from 'vitest';
import OwnershipTransfer from './OwnershipTransfer';
const owner='a'.repeat(24),recipient='b'.repeat(24),vault='c'.repeat(24);
const directory=[{id:owner,email:'owner@example.test',role:'analyst',public:{}},{id:recipient,email:'next@example.test',role:'reviewer',public:{}}];
const team={id:vault,owner,revision:1,epoch:1,rotation_required:false,grants:[{user_id:owner,accepted:true},{user_id:recipient,accepted:true}]};
const proposal={id:'d'.repeat(24),status:'pending',document:{vault_id:vault,recipient,owner,former_owner_role:'removed',expires_at:Math.floor(Date.now()/1000)+900}};
const answer=value=>({ok:true,json:async()=>({proposal:value})});
it('requires an eligible successor and an explicit retained role before proposing',async()=>{
  vi.stubGlobal('fetch',vi.fn(async()=>answer(null)));const onPropose=vi.fn();
  render(<OwnershipTransfer team={team} me={{id:owner,role:'analyst'}} directory={directory} busy={false} onPropose={onPropose}/>);
  fireEvent.click(screen.getByText('Vault ownership and handoff'));
  const button=await screen.findByRole('button',{name:'Sign ownership proposal'});
  fireEvent.click(button);expect(onPropose).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('New vault owner'),{target:{value:recipient}});
  fireEvent.change(screen.getByLabelText('Your access after transfer'),{target:{value:'removed'}});
  fireEvent.click(button);expect(onPropose).toHaveBeenCalledWith(recipient,'removed');
  expect(screen.getByLabelText('New vault owner')).toHaveValue('');
});
it('shows the recipient all consequences and requires acknowledgement before accepting',async()=>{
  vi.stubGlobal('fetch',vi.fn(async()=>answer(proposal)));const onAccept=vi.fn(),onCancel=vi.fn();
  render(<OwnershipTransfer team={team} me={{id:recipient,role:'reviewer'}} directory={directory} busy={false} onAccept={onAccept} onCancel={onCancel}/>);
  fireEvent.click(screen.getByText('Vault ownership and handoff'));
  const button=await screen.findByRole('button',{name:'Accept ownership and rotate vault key'});
  fireEvent.click(button);expect(onAccept).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.click(button);expect(onAccept).toHaveBeenCalledWith(proposal);
  fireEvent.click(screen.getByRole('button',{name:'Decline ownership transfer'}));expect(onCancel).toHaveBeenCalledWith(proposal);
  expect(screen.getByText(/revokes this vault’s browser connections/)).toBeInTheDocument();
});
it('does not offer acceptance for expired or invalidated proposals',async()=>{
  vi.stubGlobal('fetch',vi.fn(async()=>answer({...proposal,status:'stale'})));
  render(<OwnershipTransfer team={team} me={{id:recipient,role:'reviewer'}} directory={directory} busy={false}/>);
  fireEvent.click(screen.getByText('Vault ownership and handoff'));
  await screen.findByText('Transfer stale');
  expect(screen.queryByRole('button',{name:'Accept ownership and rotate vault key'})).not.toBeInTheDocument();
});
it('denies workspace viewers the ownership workflow without making requests',async()=>{
  const fetcher=vi.fn();vi.stubGlobal('fetch',fetcher);
  render(<OwnershipTransfer team={team} me={{id:recipient,role:'viewer'}} directory={directory} busy={false}/>);
  expect(screen.queryByText('Vault ownership and handoff')).not.toBeInTheDocument();expect(fetcher).not.toHaveBeenCalled();
});
it('discards late proposal responses after selecting another vault',async()=>{
  let finish;const fetcher=vi.fn().mockImplementationOnce(()=>new Promise(resolve=>{finish=resolve;})).mockResolvedValue(answer(null));vi.stubGlobal('fetch',fetcher);
  const view=render(<OwnershipTransfer team={team} me={{id:owner,role:'analyst'}} directory={directory} busy={false}/>);
  view.rerender(<OwnershipTransfer team={{...team,id:'e'.repeat(24)}} me={{id:owner,role:'analyst'}} directory={directory} busy={false}/>);
  await act(async()=>{finish(answer(proposal));});
  await waitFor(()=>expect(screen.queryByText('Loading ownership proposal…')).not.toBeInTheDocument());
  expect(screen.queryByText('Transfer pending')).not.toBeInTheDocument();
});
