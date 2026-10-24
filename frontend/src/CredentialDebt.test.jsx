import React from 'react';
import {expect,it,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
vi.mock('../../companion/extension/debt-operator',()=>({registerSharedLogins:vi.fn(),approveDebtRotation:vi.fn(),recoverDebtBinding:vi.fn(),restoreDebtLogin:vi.fn(),retireSharedLogin:vi.fn(async(session,connection,row,request)=>request(connection,'debt/'+row.id+'/retire',{confirmed:true,delegated_access_confirmed:true,shared_login_retired:true}))}));
import CredentialDebt from '../../companion/extension/CredentialDebt';
const connection={kind:'access'},base={clients:[{id:'client',name:'Client Orchard'}],systems:[],debt:{counts:{client:{peak:10,active:1}},verification:'Owner confirmation only.'}};
function opened(state){const request=vi.fn(async()=>({ok:true})),refresh=vi.fn(async()=>{});render(<CredentialDebt connection={connection} map={{...base,debt:{...base.debt,exposures:[{id:'entry',vault:'vault',client:'client',label:'Shared account',domain:'github.com',platform:'github',state}]}}} session={{material:{kind:'shared'},policy:{id:'vault'},entries:[]}} unlocked={true} request={request} refresh={refresh}/>);fireEvent.click(screen.getByText('Reduce shared-password debt'));return {request,refresh};}
it('requires both delegated-access and retirement confirmations before reducing debt',async()=>{
  const {request,refresh}=opened('verified');
  const button=screen.getByRole('button',{name:'Archive login and retire debt'});fireEvent.click(button);
  expect(request).not.toHaveBeenCalled();
  fireEvent.click(screen.getByLabelText('Delegated access works for the people who need it.'));fireEvent.click(button);
  expect(request).not.toHaveBeenCalled();
  fireEvent.click(screen.getByLabelText('The shared login has been retired from use.'));fireEvent.click(button);
  await waitFor(()=>expect(request).toHaveBeenCalledWith(connection,'debt/entry/retire',{confirmed:true,delegated_access_confirmed:true,shared_login_retired:true}));
  expect(refresh).toHaveBeenCalled();
  expect(screen.getByText('Client Orchard: shared logins 10 → 1')).toBeInTheDocument();
});
it('records verification as an explicit owner report and can reopen retired debt',async()=>{
  const {request}=opened('retired');
  fireEvent.click(screen.getByRole('button',{name:'Report shared login in use again'}));
  await waitFor(()=>expect(request).toHaveBeenCalledWith(connection,'debt/entry/reopen',{confirmed:true}));
  expect(screen.getByText(/not independent website verification/)).toBeInTheDocument();
});
