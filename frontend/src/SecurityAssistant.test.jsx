import React from 'react';
import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen,waitFor} from '@testing-library/react';
import SecurityAssistant from '../../companion/extension/SecurityAssistant';
afterEach(()=>{cleanup();vi.unstubAllGlobals();});
it('keeps consent in the popup, requests only its approved target and renders plain actions',async()=>{
  const saved={securityConnection:{kind:'security',origin:'https://service.example',token:'fixture'}};
  const browser={tabs:{query:vi.fn(async()=>[{url:'https://example.com'}])},storage:{local:{get:vi.fn(async()=>saved),set:vi.fn(async value=>Object.assign(saved,value)),remove:vi.fn(async key=>delete saved[key])}}};
  const fetcher=vi.fn(async url=>({ok:true,json:async()=>url.endsWith('/context')?{workspace:'Work',scan_hosts:['approved.example'],devices:[],ai_available:true}:url.endsWith('/operations')?{id:'a'.repeat(24),status:'queued'}:{id:'a'.repeat(24),status:'complete',ai_status:'complete',summary:'One configuration needs review.',actions:[{title:'Review your site configuration',steps:['Ask the owner to inspect its header policy'],verification:'Recheck the HTTPS response'}]}}));
  vi.stubGlobal('fetch',fetcher);render(<SecurityAssistant browser={browser}/>);
  fireEvent.click(screen.getByText('Check my security · device and project checks'));
  const run=await screen.findByRole('button',{name:'Approve and check my security'});
  expect(fetcher.mock.calls.some(([url])=>url.endsWith('/operations'))).toBe(false);
  fireEvent.click(run);
  expect(await screen.findByText('One configuration needs review.')).toBeInTheDocument();
  const operation=fetcher.mock.calls.find(([url])=>url.endsWith('/operations'));
  expect(JSON.parse(operation[1].body)).toMatchObject({authorized:true,action:'website',target:'approved.example',ai_triage:true});
  fireEvent.change(screen.getByLabelText('Check'),{target:{value:'device'}});
  await waitFor(()=>expect(screen.getByRole('button',{name:'Approve and check my security'})).toBeDisabled());
  expect(screen.getByText('Needs device helper. The hosting server is never scanned in place of your computer.')).toBeInTheDocument();
});
it('shows disabled Mac protection even when the scanner finding count is zero',async()=>{
 const saved={securityConnection:{kind:'security',origin:'https://service.example',token:'fixture'},securityOperation:{id:'a'.repeat(24),origin:'https://service.example'}};
 const browser={tabs:{query:vi.fn(async()=>[])},storage:{local:{get:vi.fn(async()=>saved),set:vi.fn(),remove:vi.fn()}}};
 vi.stubGlobal('fetch',vi.fn(async url=>({ok:true,json:async()=>url.endsWith('/context')?{workspace:'Work',scan_hosts:[],devices:[],ai_available:false}:{id:'a'.repeat(24),status:'complete',finding_count:0,posture_checks:[{id:'filevault',title:'FileVault',state:'disabled',reason:'',guidance:'Review with the device owner.'}]}})));
 render(<SecurityAssistant browser={browser}/>);fireEvent.click(screen.getByText('Check my security · device and project checks'));
 expect(await screen.findByText('FileVault: disabled')).toBeInTheDocument();expect(screen.getByText(/Review disabled and unavailable checks/)).toBeInTheDocument();
});
