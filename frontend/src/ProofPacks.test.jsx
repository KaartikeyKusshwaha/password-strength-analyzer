import React from 'react';
import {it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import ProofPacks from '../../companion/extension/ProofPacks';
import ProofHistory from './ProofHistory';
import {accessRequest} from '../../companion/extension/access-client';
const connection={kind:'access',origin:'https://service.example.test',token:'x'.repeat(54)},client='a'.repeat(24),id='b'.repeat(24);
const snapshot={client:{id:client,name:'Studio client'},access:[],reported_accounts:[],offboarding:[],people:[],limitations:'Recorded metadata, not a certification.'};
const pack={id,client,created_at:'2026-10-23',digest:'c'.repeat(64),revoked:false,links:[]};
it('previews exact scope, privately generates, and separately approves confidential sharing',async()=>{
 let generated=false;const request=vi.fn(async(_connection,path,body)=>{
  if(path==='proof-packs/context')return {assets:[]};if(path==='proof-packs'&&body){generated=true;return pack;}if(path==='proof-packs')return {packs:generated?[pack]:[]};
  if(path==='proof-packs/preview')return {source_digest:'d'.repeat(64),snapshot};if(path.endsWith('/share'))return {url:'https://service.example.test/proof#private-test-only',note:'Keep this confidential.'};
 });
 render(<ProofPacks connection={connection} map={{clients:[{id:client,name:'Studio client'}]}} request={request}/>);expect(request).not.toHaveBeenCalled();
 fireEvent.change(screen.getByLabelText('Report client'),{target:{value:client}});fireEvent.click(screen.getByRole('button',{name:'Preview exact snapshot'}));await screen.findByText('Review before generation');
 fireEvent.change(screen.getByLabelText('Current account password'),{target:{value:'fixture-only-password'}});fireEvent.change(screen.getByLabelText('Unused MFA or recovery code'),{target:{value:'fixture-code'}});fireEvent.click(screen.getByLabelText(/I reviewed this exact client metadata/));fireEvent.click(screen.getByRole('button',{name:'Generate private Proof Pack'}));
 await screen.findByText(/Immutable Proof Pack generated/);expect(request).toHaveBeenCalledWith(connection,'proof-packs',{client_id:client,brand:'Client access review',asset_ids:[],include_posture:false,approved:true,password:'fixture-only-password',code:'fixture-code',source_digest:'d'.repeat(64)});
 expect(request.mock.calls.some(([,path])=>path.endsWith('/share'))).toBe(false);
 fireEvent.click(screen.getByRole('button',{name:'Prepare a share link'}));fireEvent.change(screen.getByLabelText('Current account password'),{target:{value:'fixture-only-password'}});fireEvent.change(screen.getByLabelText('Unused MFA or recovery code'),{target:{value:'second-code'}});fireEvent.click(screen.getByLabelText(/Anyone with this link may read/));fireEvent.click(screen.getByRole('button',{name:'Approve confidential report sharing'}));
 expect(await screen.findByLabelText('Private report share link')).toHaveValue('https://service.example.test/proof#private-test-only');expect(request).toHaveBeenCalledWith(connection,'proof-packs/'+id+'/share',{approved:true,password:'fixture-only-password',code:'second-code',days:7});
});
it('changing report scope discards the old approval preview',async()=>{
 const request=vi.fn(async()=>({source_digest:'d'.repeat(64),snapshot}));render(<ProofPacks connection={connection} map={{clients:[{id:client,name:'Studio client'}]}} request={request}/>);fireEvent.change(screen.getByLabelText('Report client'),{target:{value:client}});fireEvent.click(screen.getByRole('button',{name:'Preview exact snapshot'}));await screen.findByText('Review before generation');fireEvent.click(screen.getByLabelText(/Include recorded client-staff/));expect(screen.queryByRole('button',{name:'Generate private Proof Pack'})).not.toBeInTheDocument();
});
it('checks the PDF type and exact endpoint without adding vault credentials',async()=>{
 const pdf=new Blob(['%PDF-fixture'],{type:'application/pdf'}),fetcher=vi.fn(async()=>({ok:true,headers:new Headers({'Content-Type':'application/pdf'}),blob:async()=>pdf}));
 expect(await accessRequest(connection,'proof-packs/'+id+'/pdf',undefined,fetcher,{asPdf:true})).toBe(pdf);expect(fetcher.mock.calls[0][1]).toMatchObject({credentials:'omit',redirect:'error',method:'GET'});
 expect(fetcher.mock.calls[0][1].headers).not.toHaveProperty('X-Sentinel-Vault-Token');await expect(accessRequest(connection,'proof-packs/'+id+'/pdf',undefined,fetcher,{vaultToken:'not-allowed'})).rejects.toThrow('Vault authorization');
 fetcher.mockResolvedValue({ok:true,headers:new Headers({'Content-Type':'text/html'})});await expect(accessRequest(connection,'proof-packs/'+id+'/pdf',undefined,fetcher,{asPdf:true})).rejects.toThrow('Unexpected');
});
it('keeps website history read-only and uses a same-origin authenticated PDF link',async()=>{
 vi.stubGlobal('fetch',vi.fn(async()=>({ok:true,status:200,json:async()=>({packs:[pack]})})));render(<ProofHistory/>);expect(fetch).not.toHaveBeenCalled();fireEvent.click(screen.getByRole('button',{name:'Load client Proof Packs'}));expect(await screen.findByRole('link',{name:'Download retained PDF'})).toHaveAttribute('href','/api/proof-packs/'+id+'/pdf');expect(screen.queryByRole('button',{name:/Approve/})).not.toBeInTheDocument();
});
