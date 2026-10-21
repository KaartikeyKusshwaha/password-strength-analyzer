import React from 'react';
import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen,waitFor} from '@testing-library/react';
import FileChecks from '../../companion/extension/FileChecks';
afterEach(()=>{cleanup();vi.unstubAllGlobals();});
const connection={kind:'security',origin:'https://service.example',token:'fixture'};
function authorize(){fireEvent.click(screen.getByLabelText(/I can assess this file/));}
it('only submits source after explicit disclosure consent and clears it after queuing',async()=>{
  const fetcher=vi.fn(async()=>({ok:true,json:async()=>({id:'a'.repeat(24),status:'queued'})})),onQueued=vi.fn();vi.stubGlobal('fetch',fetcher);
  render(<FileChecks connection={connection} running={false} ai={false} onQueued={onQueued}/>);
  fireEvent.change(screen.getByLabelText('Paste or drop file contents'),{target:{value:'eval(user_input)'}});
  const run=screen.getByRole('button',{name:'Approve and check Python'});expect(run).toBeDisabled();expect(fetcher).not.toHaveBeenCalled();
  authorize();fireEvent.click(run);await waitFor(()=>expect(onQueued).toHaveBeenCalled());
  expect(JSON.parse(fetcher.mock.calls[0][1].body)).toMatchObject({action:'python',content:'eval(user_input)',authorized:true,ai_triage:false});
  expect(screen.getByLabelText('Paste or drop file contents')).toHaveValue('');
});
it('requires package selection and resets disclosure approval when source changes',async()=>{
  const fetcher=vi.fn(async()=>({ok:true,json:async()=>({packages:[{id:'pin-one',ecosystem:'PyPI',name:'requests',version:'2.0.0'}],skipped:[]})}));vi.stubGlobal('fetch',fetcher);
  render(<FileChecks connection={connection} running={false} ai={false} onQueued={vi.fn()}/>);
  fireEvent.change(screen.getByLabelText('File check'),{target:{value:'dependencies'}});
  const text=screen.getByLabelText('Paste or drop file contents');fireEvent.change(text,{target:{value:'requests==2.0.0'}});authorize();
  fireEvent.click(screen.getByRole('button',{name:'Preview exact packages'}));
  const packageChoice=await screen.findByLabelText('PyPI · requests@2.0.0');
  const run=screen.getByRole('button',{name:'Approve and check selected packages'});expect(run).toBeDisabled();
  fireEvent.click(packageChoice);fireEvent.click(screen.getByLabelText(/Send only the 1 selected/));expect(run).toBeEnabled();
  fireEvent.change(text,{target:{value:'requests==2.1.0'}});expect(run).toBeDisabled();expect(screen.queryByLabelText('PyPI · requests@2.0.0')).not.toBeInTheDocument();
  expect(screen.getByLabelText(/I can assess this file/)).not.toBeChecked();expect(fetcher).toHaveBeenCalledTimes(1);
});
it('does not submit oversized content',()=>{
  const fetcher=vi.fn();vi.stubGlobal('fetch',fetcher);render(<FileChecks connection={connection} running={false} ai={false} onQueued={vi.fn()}/>);
  fireEvent.change(screen.getByLabelText('Paste or drop file contents'),{target:{value:'x'.repeat(65537)}});authorize();
  expect(screen.getByRole('button',{name:'Approve and check Python'})).toBeDisabled();expect(fetcher).not.toHaveBeenCalled();
});
it('loads a dropped UTF-8 file without transmitting it',async()=>{
  const fetcher=vi.fn();vi.stubGlobal('fetch',fetcher);render(<FileChecks connection={connection} running={false} ai={false} onQueued={vi.fn()}/>);
  const text=screen.getByLabelText('Paste or drop file contents');
  fireEvent.drop(text,{dataTransfer:{files:[{size:15,arrayBuffer:async()=>new TextEncoder().encode('print("hello")').buffer}]}});
  await waitFor(()=>expect(text).toHaveValue('print("hello")'));
  expect(fetcher).not.toHaveBeenCalled();expect(screen.getByLabelText(/I can assess this file/)).not.toBeChecked();
});
