import React from 'react';
import {expect,it,vi} from 'vitest';
import {render,screen} from '@testing-library/react';
import {Popup} from '../../companion/extension/popup';
import {runtimeVersion} from '../../companion/extension/runtime-version';
import manifest from '../../companion/extension/public/manifest.json';

it('reads the browser-loaded version instead of treating disk files as installed',()=>{
  const browser={runtime:{getManifest:()=>({version:manifest.version})}};
  expect(runtimeVersion(browser,manifest.version)).toEqual({loaded:manifest.version,bundled:manifest.version,matches:true});
  expect(runtimeVersion(browser,'0.0.1').matches).toBe(false);
});
it.each(['0.0.1',null])('blocks credential controls and connection reads when loaded version is %s',async loaded=>{
  const get=vi.fn(),query=vi.fn(),fetcher=vi.fn();
  vi.stubGlobal('fetch',fetcher);
  vi.stubGlobal('chrome',{runtime:{getManifest:()=>{if(!loaded)throw new Error('Extension context invalidated');return {version:loaded};}},storage:{local:{get}},tabs:{query}});
  render(<Popup/>);
  expect(await screen.findByRole('alert')).toHaveTextContent('Finish the companion update');
  expect(screen.getByText(/Vault controls are paused/)).toBeInTheDocument();
  expect(screen.queryByLabelText(/Master passphrase/)).not.toBeInTheDocument();
  expect(screen.queryByRole('button',{name:'Sign in and connect'})).not.toBeInTheDocument();
  expect(get).not.toHaveBeenCalled();expect(query).not.toHaveBeenCalled();expect(fetcher).not.toHaveBeenCalled();
});
it('keeps ordinary setup available when the loaded version matches its files',async()=>{
  const fetcher=vi.fn();vi.stubGlobal('fetch',fetcher);
  vi.stubGlobal('chrome',{runtime:{getManifest:()=>({version:manifest.version}),sendMessage:vi.fn(async()=>({ok:true,sites:[]}))},storage:{local:{get:vi.fn(async()=>({}))}},tabs:{query:vi.fn(async()=>[{id:1,url:'https://fixture.example.test/login'}])}});
  render(<Popup/>);
  expect(await screen.findByRole('heading',{name:'Connect your cloud vault'})).toBeInTheDocument();
  expect(screen.queryByText('Finish the companion update')).not.toBeInTheDocument();
  expect(screen.getByRole('button',{name:'Check this site'})).toBeEnabled();
  expect(fetcher).not.toHaveBeenCalled();
});
