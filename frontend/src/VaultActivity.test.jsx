import {act,fireEvent,render,screen,waitFor} from '@testing-library/react';
import {expect,it,vi} from 'vitest';
import VaultActivity from './VaultActivity';

const first='a'.repeat(24),second='b'.repeat(24);
const entry={id:'private-entry',type:'login',title:'Private client account',origin:'https://private.example',username:'private-username',password:'never-send-fixture-password',history:{version:1,events:[{kind:'change_confirmed_by_user',at:'2026-10-19T12:00:00.000Z'}]}};
function response(events,next_before=null){return {ok:true,json:async()=>({events,next_before,source:'service_record',independently_verified:false})};}
const event={id:30,action:'vault.saved',actor_label:'You',at:'2026-10-19T12:00:00+00:00'};

it('loads service records only when asked and keeps decrypted account history out of requests',async()=>{
  const fetcher=vi.fn(async()=>response([event]));vi.stubGlobal('fetch',fetcher);
  render(<VaultActivity kind="personal" vaultId={first} entries={[entry]}/>);
  expect(fetcher).not.toHaveBeenCalled();
  expect(screen.queryByText(entry.title)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'Show vault activity'}));
  expect(await screen.findByText('Encrypted vault saved')).toBeInTheDocument();
  expect(screen.getByText('Website change reported by the user')).toBeInTheDocument();
  expect(screen.getByText(entry.title)).toBeInTheDocument();
  expect(screen.getByText(/not an independently verified audit/)).toBeInTheDocument();
  expect(fetcher).toHaveBeenCalledWith('/api/vault-activity/personal/'+first,expect.objectContaining({method:'GET'}));
  for(const secret of [entry.password,entry.username,entry.origin,entry.title])expect(JSON.stringify(fetcher.mock.calls)).not.toContain(secret);
});

it('paginates older records using the server cursor and refreshes without duplicating entries',async()=>{
  const fetcher=vi.fn(async(url)=>url.includes('before=30')?response([{...event,id:20,action:'vault.created'}]):response([event],30));vi.stubGlobal('fetch',fetcher);
  render(<VaultActivity kind="personal" vaultId={first}/>);
  fireEvent.click(screen.getByRole('button',{name:'Show vault activity'}));
  fireEvent.click(await screen.findByRole('button',{name:'Load older vault events'}));
  expect(await screen.findByText('Vault space created')).toBeInTheDocument();
  expect(screen.getAllByText('Encrypted vault saved')).toHaveLength(1);
  expect(screen.queryByRole('button',{name:'Load older vault events'})).not.toBeInTheDocument();
  expect(fetcher.mock.calls[1][0]).toBe('/api/vault-activity/personal/'+first+'?before=30');
  fireEvent.click(screen.getByRole('button',{name:'Refresh vault activity'}));
  await waitFor(()=>expect(screen.queryByText('Vault space created')).not.toBeInTheDocument());
});

it('drops private observations immediately when the vault locks',async()=>{
  vi.stubGlobal('fetch',vi.fn(async()=>response([])));
  const view=render(<VaultActivity kind="personal" vaultId={first} entries={[entry]}/>);
  fireEvent.click(screen.getByRole('button',{name:'Show vault activity'}));
  await screen.findByText(entry.title);
  view.rerender(<VaultActivity kind="personal" vaultId={first} entries={null}/>);
  expect(screen.queryByText(entry.title)).not.toBeInTheDocument();
  expect(screen.getByText('Unlock this vault to see its private account observations.')).toBeInTheDocument();
});

it('does not publish a late response after changing vault scope',async()=>{
  let finish;const fetcher=vi.fn(()=>new Promise(resolve=>{finish=resolve;}));vi.stubGlobal('fetch',fetcher);
  const view=render(<VaultActivity kind="personal" vaultId={first}/>);
  fireEvent.click(screen.getByRole('button',{name:'Show vault activity'}));
  view.rerender(<VaultActivity kind="shared" vaultId={second}/>);
  await act(async()=>{finish(response([event]));});
  expect(screen.getByRole('button',{name:'Show vault activity'})).toBeInTheDocument();
  expect(screen.queryByText('Encrypted vault saved')).not.toBeInTheDocument();
});

it('shows access removal and clears stale service events rather than treating failure as empty activity',async()=>{
  const fetcher=vi.fn().mockResolvedValueOnce(response([event])).mockResolvedValueOnce({ok:false,status:404,json:async()=>({detail:'Vault activity not found or access removed'})});vi.stubGlobal('fetch',fetcher);
  render(<VaultActivity kind="shared" vaultId={first}/>);
  fireEvent.click(screen.getByRole('button',{name:'Show vault activity'}));
  await screen.findByText('Encrypted vault saved');
  fireEvent.click(screen.getByRole('button',{name:'Refresh vault activity'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('access removed');
  expect(screen.queryByText('Encrypted vault saved')).not.toBeInTheDocument();
  expect(screen.queryByText(/No service events/)).not.toBeInTheDocument();
});

it('keeps unavailable, malformed and bounded local history honest',async()=>{
  vi.stubGlobal('fetch',vi.fn(async()=>response([])));
  render(<VaultActivity kind="personal" vaultId={first} entries={[{...entry,history:undefined},{...entry,id:'bad-history',history:{version:5,events:[{kind:'made-up',at:'tomorrow'}]}}]}/>);
  fireEvent.click(screen.getByRole('button',{name:'Show vault activity'}));
  expect(await screen.findByText(/No service events have been recorded/)).toBeInTheDocument();
  expect(screen.getByText('2 account(s) have no supported recorded history.')).toBeInTheDocument();
  expect(screen.getByText('No encrypted account observations are available.')).toBeInTheDocument();
  expect(screen.getByText(/latest eight observations per current account/)).toBeInTheDocument();
});

it('closing activity cancels late results and removes local account titles',async()=>{
  let finish;vi.stubGlobal('fetch',vi.fn(()=>new Promise(resolve=>{finish=resolve;})));
  render(<VaultActivity kind="personal" vaultId={first} entries={[entry]}/>);
  fireEvent.click(screen.getByRole('button',{name:'Show vault activity'}));
  expect(screen.getByText(entry.title)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'Hide vault activity'}));
  await act(async()=>{finish(response([event]));});
  expect(screen.queryByText(entry.title)).not.toBeInTheDocument();
  expect(screen.queryByText('Encrypted vault saved')).not.toBeInTheDocument();
});

it('pages all retained account observations locally without extra service requests',async()=>{
  const fetcher=vi.fn(async()=>response([]));vi.stubGlobal('fetch',fetcher);
  const entries=Array.from({length:7},(_,index)=>({...entry,id:'entry-'+index,title:'Private account '+index,history:{version:1,events:Array.from({length:8},(_,offset)=>({kind:'reviewed',at:new Date(Date.UTC(2026,9,19,12,index,offset)).toISOString()}))}}));
  render(<VaultActivity kind="personal" vaultId={first} entries={entries}/>);
  fireEvent.click(screen.getByRole('button',{name:'Show vault activity'}));
  await screen.findByText(/No service events have been recorded/);
  expect(screen.getAllByText('Account marked reviewed')).toHaveLength(50);
  fireEvent.click(screen.getByRole('button',{name:'Show older account observations'}));
  expect(screen.getAllByText('Account marked reviewed')).toHaveLength(56);
  expect(screen.queryByRole('button',{name:'Show older account observations'})).not.toBeInTheDocument();
  expect(fetcher).toHaveBeenCalledTimes(1);
});
