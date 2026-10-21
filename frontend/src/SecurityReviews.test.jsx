import {beforeEach,expect,it,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import SecurityReviews from './SecurityReviews';
import {api} from './api';
vi.mock('./api',()=>({api:vi.fn()}));
const me={id:'owner',role:'owner',workspace:'a'.repeat(24)};
const data={integrations:{groq_configured:true,local_device_agent:true,scan_hosts:['approved.example']},devices:[],operations:[],jobs:[],security_reviews:[]};
beforeEach(()=>{api.mockReset().mockResolvedValue({id:'review'});});

it('previews multiple checks and sends the approved scope once, then clears raw draft content',async()=>{
  const refresh=vi.fn(async()=>{});
  render(<SecurityReviews data={data} me={me} canWrite refresh={refresh} go={vi.fn()}/>);
  fireEvent.change(screen.getByLabelText('Python source'),{target:{value:'private-fixture-source'}});
  fireEvent.click(screen.getByRole('button',{name:'Add check to review'}));
  fireEvent.change(screen.getByLabelText('Check type'),{target:{value:'email'}});
  fireEvent.change(screen.getByLabelText('Message text'),{target:{value:'private-fixture-message'}});
  fireEvent.click(screen.getByRole('button',{name:'Add check to review'}));
  expect(api).not.toHaveBeenCalled();
  expect(screen.getByRole('heading',{name:'Review scope · 2/6 checks'})).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Review name'),{target:{value:'My approved review'}});
  fireEvent.click(screen.getByLabelText(/I own or am authorized/));
  fireEvent.click(screen.getByLabelText(/After the checks/));
  fireEvent.click(screen.getByRole('button',{name:'Approve and run review'}));
  await waitFor(()=>expect(refresh).toHaveBeenCalled());
  expect(api).toHaveBeenCalledTimes(1);
  expect(api).toHaveBeenCalledWith('/security-reviews',{workspace_id:me.workspace,name:'My approved review',authorized:true,ai_triage:true,checks:[{action:'python',authorized:true,content:'private-fixture-source'},{action:'email',authorized:true,content:'private-fixture-message'}]});
  expect(screen.getByLabelText('Message text')).toHaveValue('');
  expect(screen.getByRole('heading',{name:'Review scope · 0/6 checks'})).toBeInTheDocument();
});

it('retains a rejected draft and shows its failure without claiming a run started',async()=>{
  api.mockRejectedValue(new Error('Workspace changed'));
  render(<SecurityReviews data={data} me={me} canWrite refresh={vi.fn()} go={vi.fn()}/>);
  fireEvent.change(screen.getByLabelText('Python source'),{target:{value:'pass'}});
  fireEvent.click(screen.getByRole('button',{name:'Add check to review'}));
  fireEvent.change(screen.getByLabelText('Review name'),{target:{value:'My review'}});
  fireEvent.click(screen.getByLabelText(/I own or am authorized/));
  fireEvent.click(screen.getByRole('button',{name:'Approve and run review'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('Workspace changed');
  expect(screen.getByRole('heading',{name:'Review scope · 1/6 checks'})).toBeInTheDocument();
  expect(screen.queryByText(/Approved review started/)).not.toBeInTheDocument();
});

it('reports partial step coverage and limits AI counts without claiming remediation',()=>{
  const review={id:'review',name:'Recorded review',status:'partial',created_at:'2026-10-21T00:00:00Z',created_by:me.id,finding_ids:['f1','f2'],ai_triage:true,triage_status:'complete',triage_count:1,agent_job:'job',checks:[{index:0,action:'device',target:'127.0.0.1',status:'unassessed',error:'Device timed out'}]};
  render(<SecurityReviews data={{...data,security_reviews:[review]}} me={me} canWrite refresh={vi.fn()} go={vi.fn()}/>);
  expect(screen.getByText('AI planning: complete · 1/2 findings included')).toBeInTheDocument();
  expect(screen.getByText('Device timed out')).toBeInTheDocument();
  expect(screen.getByText(/do not establish that findings were fixed/)).toBeInTheDocument();
  expect(screen.queryByRole('button',{name:'Cancel remaining review work'})).not.toBeInTheDocument();
});

it('prevents viewer approvals and a second run while a workspace reservation is active',()=>{
  const {rerender}=render(<SecurityReviews data={data} me={{...me,role:'viewer'}} canWrite={false} refresh={vi.fn()} go={vi.fn()}/>);
  expect(screen.getByRole('button',{name:'Add check to review'})).toBeDisabled();
  rerender(<SecurityReviews data={{...data,operations:[{status:'queued'}]}} me={me} canWrite refresh={vi.fn()} go={vi.fn()}/>);
  expect(screen.getByRole('button',{name:'Approve and run review'})).toBeDisabled();
  expect(screen.getByRole('status')).toHaveTextContent('Another review, assessment or agent workflow is active');
});

it('shows the actual child scan coverage inside a partial review',()=>{
  const review={id:'review',name:'Local review',status:'partial',created_at:'2026-10-21T00:00:00Z',created_by:me.id,finding_ids:[],triage_status:'not_requested',checks:[{index:0,action:'posture',target:'127.0.0.1',status:'partial',scan_id:'scan'}]};
  const scan={id:'scan',posture:{platform:'windows',generated_at:'2026-10-21T00:00:00Z',checks:[{id:'system_disk',state:'unassessed',reason:'permission_denied'}]}};
  render(<SecurityReviews data={{...data,security_reviews:[review],scans:[scan]}} me={me} canWrite refresh={vi.fn()} go={vi.fn()}/>);
  expect(screen.getByRole('heading',{name:'Host protection observations'})).toBeInTheDocument();
  expect(screen.getByText('permission denied')).toBeInTheDocument();
  expect(screen.getByText('unassessed')).toBeInTheDocument();
});
