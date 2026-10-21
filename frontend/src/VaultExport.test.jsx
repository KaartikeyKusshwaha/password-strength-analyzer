import {fireEvent,render,screen} from '@testing-library/react';
import {expect,it,vi} from 'vitest';
import VaultExport from './VaultExport';
import {downloadCredentialCsv} from './credential-export';
vi.mock('./credential-export',async importOriginal=>({...await importOriginal(),downloadCredentialCsv:vi.fn()}));
const entries=[{id:'a',type:'login',title:'Account',origin:'https://example.com',username:'user',password:'disposable'}, {id:'b',type:'login',title:'Archived',origin:'https://example.com',password:'old',history:{version:1,events:[],archived_at:'2026-10-21T00:00:00.000Z'}}];
function open(){fireEvent.click(screen.getByText('Move logins to another password manager'));}

it('downloads only after explicit approval and clears approval after use or selection changes',()=>{
  downloadCredentialCsv.mockClear();render(<VaultExport entries={entries}/>);open();
  const button=screen.getByRole('button',{name:'Download plaintext login CSV'}),approve=screen.getByLabelText(/I understand this downloads/);
  expect(button).toBeDisabled();expect(downloadCredentialCsv).not.toHaveBeenCalled();
  expect(screen.getByText('1 login entries selected for export.')).toBeVisible();
  fireEvent.click(approve);fireEvent.click(screen.getByLabelText('Include archived login entries'));
  expect(approve).not.toBeChecked();expect(button).toBeDisabled();
  fireEvent.click(approve);fireEvent.click(button);
  expect(downloadCredentialCsv).toHaveBeenCalledExactlyOnceWith(entries,true);
  expect(button).toBeDisabled();expect(screen.getByRole('status')).toHaveTextContent('download requested');
});

it('invalidates approval if vault contents change and never renders a password preview',()=>{
  const {rerender,unmount}=render(<VaultExport entries={entries}/>);open();
  const approval=screen.getByLabelText(/I understand this downloads/);fireEvent.click(approval);
  rerender(<VaultExport entries={entries.map(entry=>({...entry,password:'changed'}))}/>);
  expect(approval).not.toBeChecked();expect(screen.getByRole('button',{name:'Download plaintext login CSV'})).toBeDisabled();
  expect(screen.queryByText('disposable')).not.toBeInTheDocument();expect(screen.queryByText('changed')).not.toBeInTheDocument();
  unmount();render(<VaultExport entries={entries} disabled/>);open();
  expect(screen.getByLabelText(/I understand this downloads/)).toBeDisabled();
});

it('reports a failed download without claiming that a file was saved',()=>{
  downloadCredentialCsv.mockImplementationOnce(()=>{throw new Error('Download unavailable');});
  render(<VaultExport entries={entries}/>);open();
  fireEvent.click(screen.getByLabelText(/I understand this downloads/));fireEvent.click(screen.getByRole('button',{name:'Download plaintext login CSV'}));
  expect(screen.getByRole('alert')).toHaveTextContent('Download unavailable');expect(screen.queryByRole('status')).not.toBeInTheDocument();
});
