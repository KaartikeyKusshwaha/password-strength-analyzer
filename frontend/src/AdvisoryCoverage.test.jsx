import {expect,it} from 'vitest';
import {render,screen} from '@testing-library/react';
import AdvisoryCoverage from './AdvisoryCoverage';

it('distinguishes missing legacy coverage, partial grouping and successful alias lookups',()=>{
  const {rerender,container}=render(<AdvisoryCoverage/>);
  expect(container).toBeEmptyDOMElement();
  rerender(<AdvisoryCoverage coverage={{completed:1,total:3,grouped_matches:1,status:'partial'}}/>);
  expect(screen.getByRole('status')).toHaveTextContent('1/3 records checked');
  expect(screen.getByRole('status')).toHaveTextContent('remaining matches are kept separately and may overlap');
  rerender(<AdvisoryCoverage coverage={{completed:3,total:3,grouped_matches:2,status:'complete'}}/>);
  expect(screen.getByRole('status')).not.toHaveTextContent('incomplete');
  expect(screen.getByRole('status')).toHaveTextContent('separate from package assessment coverage');
});

it('shows CVSS coverage independently of a completed detail lookup',()=>{
  render(<AdvisoryCoverage coverage={{completed:3,total:3,grouped_matches:1,status:'complete',severity:{scored:1,total:2,partial:1}}}/>);
  expect(screen.getByRole('status')).toHaveTextContent('3/3 records checked');
  expect(screen.getByRole('status')).toHaveTextContent('1/2 grouped matches have a usable base rating; 1 have incomplete rating evidence');
  expect(screen.getByRole('status')).toHaveTextContent('Missing ratings remain unknown');
});
