import React from 'react';
import {it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import AccessReviews from '../../companion/extension/AccessReviews';
import {accessRequest} from '../../companion/extension/access-client';
const connection={kind:'access',origin:'https://service.example.test',token:'x'.repeat(54)};
const review={id:'a'.repeat(24),job:'b'.repeat(24),status:'ready',review_digest:'c'.repeat(64),evidence:{candidate_count:2,omitted:1,items:[{key:'debt:1',client:'client',detail:'Owner-reported shared login debt.'}]},references:{f1:{client:'client',detail:'Owner-reported shared login debt.'}},coverage:'Follow-up tasks only.',plan:{summary:'Review the recorded access.',recommendations:[{finding_id:'f1',priority_reason:'Review shared access.',actions:['Confirm delegated access.'],verification:'Ask the owner to verify.'}]}};
it('loads on request and signs the exact draft with cleared transient credentials',async()=>{
 let signed=false;const request=vi.fn(async(_connection,path,body)=>{
  if(path==='reviews')return {provider_ready:true,policy:{enabled:true,expires:1900000000,next_due:1800000000},reviews:[signed?{...review,status:'signed_off',signed_at:'2026-10-23',tasks:['task']}:review]};
  if(path.endsWith('/signoff')){signed=true;return {tasks:['task'],partial:true};}
 });
 render(<AccessReviews connection={connection} map={{clients:[{id:'client',name:'Agency client'}],people:[]}} request={request}/>);
 expect(request).not.toHaveBeenCalled();fireEvent.click(screen.getByRole('button',{name:'Refresh weekly reviews'}));
 await screen.findByText('Access review ready');expect(screen.getByText(/1 omitted/)).toBeInTheDocument();
 fireEvent.change(screen.getByLabelText('Current account password'),{target:{value:'Disposable test password'}});fireEvent.change(screen.getByLabelText('Unused MFA or recovery code'),{target:{value:'unused-recovery'}});
 fireEvent.click(screen.getByLabelText(/I reviewed this exact evidence/));fireEvent.click(screen.getByRole('button',{name:'Sign off and create follow-up tasks'}));
 await waitFor(()=>expect(request).toHaveBeenCalledWith(connection,'reviews/'+review.id+'/signoff',{approved:true,password:'Disposable test password',code:'unused-recovery',review_digest:review.review_digest}));
 expect(await screen.findByRole('status')).toHaveTextContent('Omitted evidence still needs another review');expect(screen.queryByLabelText('Current account password')).not.toBeInTheDocument();
});
it('enables a bounded weekly metadata policy, but never when the provider is unavailable',async()=>{
 const request=vi.fn(async()=>({policy:null,reviews:[],provider_ready:false}));render(<AccessReviews connection={connection} request={request}/>);fireEvent.click(screen.getByRole('button',{name:'Refresh weekly reviews'}));
 expect(await screen.findByRole('button',{name:'Enable weekly reviews'})).toBeDisabled();expect(screen.getByText(/No substitute AI plan/)).toBeInTheDocument();
});
it('limits review transport to exact read and approval endpoints without vault headers or cookies',async()=>{
 const fetcher=vi.fn(async()=>({ok:true,json:async()=>({})}));await accessRequest(connection,'reviews',undefined,fetcher);await accessRequest(connection,'reviews/'+review.id+'/signoff',{review_digest:review.review_digest},fetcher);
 expect(fetcher.mock.calls[0][1]).toMatchObject({credentials:'omit',redirect:'error',method:'GET'});
 expect(fetcher.mock.calls[1][1].headers).not.toHaveProperty('X-Sentinel-Vault-Token');
 await expect(accessRequest(connection,'reviews/../../vault',{},fetcher)).rejects.toThrow('Unsupported');
 await expect(accessRequest(connection,'reviews',{},fetcher,{vaultToken:'secret'})).rejects.toThrow('Vault authorization');
 expect(fetcher).toHaveBeenCalledTimes(2);
});
