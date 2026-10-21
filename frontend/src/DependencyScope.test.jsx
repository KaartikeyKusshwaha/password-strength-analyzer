import {useState} from 'react';
import {beforeEach,expect,it,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import DependencyScope,{emptyDependency} from './DependencyScope';
import {api} from './api';
vi.mock('./api',()=>({api:vi.fn()}));
export const previewFixture={packages:[{id:'first',ecosystem:'npm',name:'example',version:'1.0.0'},{id:'second',ecosystem:'npm',name:'example',version:'2.0.0'}],coverage:{unique_packages:2,selected:2,excluded:0,skipped_records:1,root_records:1,duplicate_records:0,skipped_reasons:{'Unsupported source':1}}};
function Harness(){const [value,change]=useState(emptyDependency);return <><DependencyScope value={value} onChange={change}/><output aria-label="Draft">{JSON.stringify(value)}</output></>;}
beforeEach(()=>{api.mockReset().mockResolvedValue(previewFixture);});
it('previews without starting a scan, keeps duplicate names with distinct versions and clears consent on scope changes',async()=>{
  render(<Harness/>);
  fireEvent.change(screen.getByLabelText('Dependency format'),{target:{value:'package-lock'}});
  fireEvent.change(screen.getByLabelText('Dependency source'),{target:{value:'fixture-source'}});
  fireEvent.click(screen.getByRole('button',{name:'Preview package scope'}));
  await screen.findByLabelText('npm · example@2.0.0');
  expect(api).toHaveBeenCalledExactlyOnceWith('/dependency-inventory/preview',{content:'fixture-source',format:'package-lock'});
  fireEvent.click(screen.getByLabelText(/I approve sending/));
  expect(JSON.parse(screen.getByLabelText('Draft').textContent).dependency_consent).toBe(true);
  fireEvent.click(screen.getByLabelText('npm · example@1.0.0'));
  expect(JSON.parse(screen.getByLabelText('Draft').textContent)).toMatchObject({dependency_selection:['second'],dependency_consent:false});
  fireEvent.change(screen.getByLabelText('Dependency source'),{target:{value:'changed'}});
  expect(screen.queryByLabelText('npm · example@2.0.0')).not.toBeInTheDocument();
  expect(JSON.parse(screen.getByLabelText('Draft').textContent)).toMatchObject({dependency_selection:null,dependency_consent:false});
});
it('ignores a preview response after the source changed',async()=>{
  let finish;api.mockImplementation(()=>new Promise(resolve=>{finish=resolve;}));
  render(<Harness/>);
  fireEvent.change(screen.getByLabelText('Dependency source'),{target:{value:'old'}});
  fireEvent.click(screen.getByRole('button',{name:'Preview package scope'}));
  fireEvent.change(screen.getByLabelText('Dependency source'),{target:{value:'new'}});
  finish(previewFixture);
  await waitFor(()=>expect(screen.getByLabelText('Dependency source')).toHaveValue('new'));
  expect(screen.queryByLabelText(/I approve sending/)).not.toBeInTheDocument();
});
