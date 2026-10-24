import React from 'react';
import {afterEach,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen,waitFor} from '@testing-library/react';
import SiteCheck from '../../companion/extension/SiteCheck';
afterEach(()=>{cleanup();vi.unstubAllGlobals();});
function browser(granted=true,changed=false){let count=0;return {tabs:{query:vi.fn(async()=>[{url:changed&&count++?'https://other.example/':'https://example.com/login?private=1'}])},permissions:{request:vi.fn(async()=>granted)}};}
it('requires an exact-site grant and shows results inside the extension',async()=>{
  const b=browser(),fetcher=vi.fn(async()=>({status:200,headers:new Headers()}));vi.stubGlobal('fetch',fetcher);
  render(<SiteCheck browser={b}/>);
  await waitFor(()=>expect(screen.getByRole('button',{name:'Check this site'})).not.toBeDisabled());
  expect(fetcher).not.toHaveBeenCalled();fireEvent.click(screen.getByRole('button',{name:'Check this site'}));
  expect(await screen.findByText('3 things to review')).toBeInTheDocument();
  expect(b.permissions.request).toHaveBeenCalledWith({origins:['https://example.com/*']});
  expect(screen.getByText(/This is not a verdict/)).toBeInTheDocument();
});
it.each([[false,false,'declined'],[true,true,'changed']])('does not assess after denial or tab navigation',async(granted,changed,message)=>{
  const fetcher=vi.fn();vi.stubGlobal('fetch',fetcher);render(<SiteCheck browser={browser(granted,changed)}/>);
  await waitFor(()=>expect(screen.getByRole('button',{name:'Check this site'})).not.toBeDisabled());
  fireEvent.click(screen.getByRole('button',{name:'Check this site'}));
  expect(await screen.findByRole('alert')).toHaveTextContent(message);expect(fetcher).not.toHaveBeenCalled();
});
