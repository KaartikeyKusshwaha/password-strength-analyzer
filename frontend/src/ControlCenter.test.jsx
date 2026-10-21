import React from 'react';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import ControlCenter from './ControlCenter';

it('starts a device check directly from a target with explicit authority and no prerequisite asset form', async () => {
  const refresh=vi.fn(),go=vi.fn(),fetcher=vi.fn(async()=>({ok:true,json:async()=>({status:'queued'})}));
  vi.stubGlobal('fetch',fetcher);
  render(<ControlCenter data={{operations:[],integrations:{local_device_agent:true,groq_configured:false}}} refresh={refresh} go={go} canWrite/>);
  fireEvent.change(screen.getByLabelText('Device IP address'),{target:{value:'192.168.1.10'}});
  fireEvent.change(screen.getByLabelText('TCP ports'),{target:{value:'22,443'}});
  fireEvent.click(screen.getByLabelText('I own this target or have permission to assess it.'));
  fireEvent.click(screen.getByRole('button',{name:'Run security operator'}));
  await waitFor(()=>expect(fetcher).toHaveBeenCalledTimes(1));
  const [url,options]=fetcher.mock.calls[0];expect(url).toBe('/api/operations');
  expect(JSON.parse(options.body)).toEqual({action:'device',target:'192.168.1.10',ports:[22,443],content:'',format:'requirements',authorized:true,ai_triage:false,device_id:'local'});
  await waitFor(()=>expect(refresh).toHaveBeenCalled());
  expect(screen.queryByText(/training workspace/i)).not.toBeInTheDocument();
});
it('blocks device execution on a hosted server without a local connection', () => {
  render(<ControlCenter data={{operations:[],integrations:{local_device_agent:false}}} refresh={()=>{}} go={()=>{}} canWrite/>);
  expect(screen.getByRole('button',{name:'Run security operator'})).toBeDisabled();
  expect(screen.getByText(/will not scan the hosting server/)).toBeInTheDocument();
});
it('routes account protection to the encrypted vault rather than a separate password test panel', () => {
  const go=vi.fn();
  render(<ControlCenter data={{operations:[],integrations:{local_device_agent:true}}} refresh={()=>{}} go={go} canWrite/>);
  fireEvent.click(screen.getByRole('button',{name:/Protect my accounts/}));
  fireEvent.click(screen.getByRole('button',{name:/Open my accounts/}));
  expect(go).toHaveBeenCalledWith('vault');
});
it('dispatches host checks to the selected consented agent without substituting the cloud server or a LAN address',async()=>{
  const fetcher=vi.fn(async()=>({ok:true,json:async()=>({status:'queued'})}));vi.stubGlobal('fetch',fetcher);
  render(<ControlCenter data={{operations:[],devices:[{id:'remote-fixture',label:'Work PC',allow_posture:true}],integrations:{local_device_agent:false}}} refresh={vi.fn()} go={vi.fn()} canWrite/>);
  fireEvent.change(screen.getByLabelText('Device assessment'),{target:{value:'posture'}});
  expect(screen.queryByLabelText('Device IP address')).not.toBeInTheDocument();expect(screen.queryByLabelText('TCP ports')).not.toBeInTheDocument();
  fireEvent.click(screen.getByLabelText('I own this target or have permission to assess it.'));
  fireEvent.click(screen.getByRole('button',{name:'Run security operator'}));
  await waitFor(()=>expect(fetcher).toHaveBeenCalledTimes(1));
  expect(JSON.parse(fetcher.mock.calls[0][1].body)).toMatchObject({action:'posture',target:'127.0.0.1',device_id:'remote-fixture',authorized:true});
});
it('does not offer a ports-only remote connection for host protection checks',()=>{
  render(<ControlCenter data={{operations:[],devices:[{id:'ports-only',label:'Ports only',allow_posture:false}],integrations:{local_device_agent:false}}} refresh={vi.fn()} go={vi.fn()} canWrite/>);
  fireEvent.change(screen.getByLabelText('Device assessment'),{target:{value:'posture'}});
  expect(screen.getByRole('button',{name:'Run security operator'})).toBeDisabled();
  expect(screen.getByText(/No device connection has granted host posture/)).toBeInTheDocument();
});
it('routes an addressed ownership request directly to shared vault review without accepting it',()=>{
  const go=vi.fn();
  render(<ControlCenter data={{operations:[],ownership_requests:[{id:'proposal',vault_name:'Client handoff',expires_at:Math.floor(Date.now()/1000)+900}],integrations:{local_device_agent:true}}} refresh={vi.fn()} go={go} canWrite/>);
  expect(screen.getByText('Client handoff')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'Review shared vault ownership'}));
  expect(go).toHaveBeenCalledWith('shared-vaults');
  expect(screen.getByText(/Ownership has not changed yet/)).toBeInTheDocument();
});

it('requires a separately granted device for hosted update checks and submits the selected scope',async()=>{
  const fetcher=vi.fn(async()=>({ok:true,json:async()=>({status:'queued'})}));vi.stubGlobal('fetch',fetcher);
  render(<ControlCenter data={{operations:[],devices:[{id:'posture-only',label:'Protection PC',allow_posture:true},{id:'update-fixture',label:'Update PC',allow_updates:true}],integrations:{local_device_agent:false}}} refresh={vi.fn()} go={vi.fn()} canWrite/>);
  fireEvent.change(screen.getByLabelText('Device assessment'),{target:{value:'updates'}});
  expect(screen.queryByRole('option',{name:/Protection PC/})).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Run on this device connection'),{target:{value:'update-fixture'}});
  fireEvent.click(screen.getByLabelText(/I own this target/));
  fireEvent.click(screen.getByRole('button',{name:'Run security operator'}));
  await screen.findByText(/Operator started/);
  const body=JSON.parse(fetcher.mock.calls.find(([url])=>url==='/api/operations')[1].body);
  expect(body).toMatchObject({action:'updates',target:'127.0.0.1',device_id:'update-fixture',authorized:true});
});

it('labels recorded finding counts separately from update observations',()=>{
  render(<ControlCenter data={{integrations:{local_device_agent:true},operations:[{id:'updates-finished',action:'updates',target:'127.0.0.1',status:'complete',created_at:'2026-10-21T00:00:00Z',steps:[],scan_id:'scan',finding_ids:[]}],scans:[{id:'scan',updates:{platform:'windows',generated_at:'2026-10-21T00:00:00Z',cache:{state:'observed',pending:0,security:0},reboot:{state:'observed',required:false}}}]}} refresh={vi.fn()} go={vi.fn()} canWrite/>);
  expect(screen.getByText('0 findings recorded.')).toBeInTheDocument();
  expect(screen.getByRole('heading',{name:'Windows Update observations'})).toBeInTheDocument();
});
