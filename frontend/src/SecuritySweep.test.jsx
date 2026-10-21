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
