import React from 'react';
import { fireEvent, render, screen } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import BreachReview from './BreachReview';

it('requires run consent, sends only hash prefixes and deduplicates identical local passwords',async()=>{
  vi.stubGlobal('crypto',webcrypto);
  const fetcher=vi.fn(async()=>({ok:true,text:async()=> '1E4C9B93F3F0682250B6CF8331B7EE68FD8:42'}));vi.stubGlobal('fetch',fetcher);
  render(<BreachReview entries={[{id:'a',type:'login',title:'Site A',password:'password'},{id:'b',type:'login',title:'Site B',password:'password'}]}/>);
  expect(screen.getByRole('button',{name:'Run private breach checks'})).toBeDisabled();expect(fetcher).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('checkbox'));
  fireEvent.click(screen.getByRole('button',{name:'Run private breach checks'}));
  expect(await screen.findAllByText(/found in breach dataset/)).toHaveLength(2);
  expect(fetcher).toHaveBeenCalledTimes(1);expect(fetcher.mock.calls[0][0]).toBe('https://api.pwnedpasswords.com/range/5BAA6');
  expect(JSON.stringify(fetcher.mock.calls)).not.toContain('Site A');
});
it('reports an unavailable service rather than a safe result',async()=>{
  vi.stubGlobal('crypto',webcrypto);vi.stubGlobal('fetch',vi.fn(async()=>({ok:false})));
  render(<BreachReview entries={[{id:'a',type:'login',title:'Site A',password:'fixture'}]}/>);
  fireEvent.click(screen.getByRole('checkbox'));fireEvent.click(screen.getByRole('button',{name:'Run private breach checks'}));
  expect(await screen.findByText(/service unavailable/)).toBeInTheDocument();
});
