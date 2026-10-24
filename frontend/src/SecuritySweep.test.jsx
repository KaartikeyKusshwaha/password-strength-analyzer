import {fireEvent,render,screen,waitFor} from '@testing-library/react';
import {expect,it,vi} from 'vitest';
import SecuritySweep from './SecuritySweep';
import {api} from './api';
vi.mock('./api',()=>({api:vi.fn(async()=>({id:'review'}))}));
it('starts the available device tools and AI work after a single explicit scope approval',async()=>{
  api.mockClear();const go=vi.fn(),refresh=vi.fn();
  render(<SecuritySweep data={{integrations:{local_device_agent:true,groq_configured:true}}} me={{workspace:'workspace'}} canWrite go={go} refresh={refresh}/>);
  expect(api).not.toHaveBeenCalled();
  fireEvent.click(screen.getByLabelText('I authorize these checks on my selected device.'));
  fireEvent.click(screen.getByRole('button',{name:'Approve and run agents'}));
  await waitFor(()=>expect(go).toHaveBeenCalledWith('reviews'));
  const body=api.mock.calls[0][1];expect(body.ai_triage).toBe(true);
  expect(body.checks.map(v=>v.action)).toEqual(['device','posture','updates']);
  expect(body.checks[0].ports).toContain(8110);expect(body.authorized).toBe(true);
});
it('includes only separately granted tools on a paired device',async()=>{
  api.mockClear();const go=vi.fn();
  render(<SecuritySweep data={{integrations:{local_device_agent:false,groq_configured:false},devices:[{id:'paired',label:'Work PC',allow_posture:true,allow_updates:false}]}} me={{workspace:'workspace'}} canWrite go={go} refresh={vi.fn()}/>);
  fireEvent.click(screen.getByLabelText('I authorize these checks on my selected device.'));
  fireEvent.click(screen.getByRole('button',{name:'Approve and run agents'}));
  await waitFor(()=>expect(go).toHaveBeenCalled());
  expect(api.mock.calls[0][1].checks.map(v=>v.action)).toEqual(['device','posture']);
  expect(api.mock.calls[0][1].checks.every(v=>v.device_id==='paired')).toBe(true);
});

it('requires fresh approval after changing device or AI scope, including switching back',()=>{
  api.mockClear();
  render(<SecuritySweep data={{integrations:{local_device_agent:true,groq_configured:true},devices:[{id:'paired',label:'Work PC'}]}} me={{workspace:'workspace'}} canWrite go={vi.fn()} refresh={vi.fn()}/>);
  const approval=screen.getByLabelText('I authorize these checks on my selected device.'),run=screen.getByRole('button',{name:'Approve and run agents'});
  expect(run).toBeDisabled();fireEvent.click(approval);expect(run).toBeEnabled();
  fireEvent.change(screen.getByLabelText('Device for automatic check'),{target:{value:'paired'}});
  expect(approval).not.toBeChecked();expect(run).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Device for automatic check'),{target:{value:'local'}});
  expect(approval).not.toBeChecked();
  fireEvent.click(approval);fireEvent.click(screen.getByLabelText(/Automatically prioritize/));
  expect(approval).not.toBeChecked();expect(run).toBeDisabled();expect(api).not.toHaveBeenCalled();
});

it('invalidates approval on permission changes and never substitutes a revoked device',()=>{
  api.mockClear();
  const base={integrations:{local_device_agent:false,groq_configured:false},devices:[{id:'paired',label:'Work PC',allow_posture:false,targets:['127.0.0.1']}]};
  const props={me:{workspace:'workspace'},canWrite:true,go:vi.fn(),refresh:vi.fn()};
  const {rerender}=render(<SecuritySweep {...props} data={base}/>);
  const approval=screen.getByLabelText('I authorize these checks on my selected device.');fireEvent.click(approval);
  rerender(<SecuritySweep {...props} data={{...base,devices:base.devices.map(device=>({...device,seen:Date.now()/1000}))}}/>);
  expect(approval).toBeChecked();
  rerender(<SecuritySweep {...props} data={{...base,devices:[{...base.devices[0],allow_posture:true}]}}/>);
  expect(approval).not.toBeChecked();fireEvent.click(approval);
  rerender(<SecuritySweep {...props} data={{...base,integrations:{local_device_agent:true},devices:[]}}/>);
  expect(approval).not.toBeChecked();expect(approval).toBeDisabled();
  expect(screen.getByRole('button',{name:'Approve and run agents'})).toBeDisabled();
  expect(screen.getByText(/selected device connection is no longer available/)).toBeInTheDocument();expect(api).not.toHaveBeenCalled();
  fireEvent.submit(screen.getByRole('button',{name:'Approve and run agents'}).closest('form'));
  expect(api).not.toHaveBeenCalled();
});
