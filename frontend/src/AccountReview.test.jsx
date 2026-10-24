import {expect,it,vi} from 'vitest';
import {fireEvent,render,screen,waitFor} from '@testing-library/react';
import AccountReview from './AccountReview';
import {applyReview} from './account-review';
const entry={id:'fixture-entry',type:'login',title:'Fixture account',origin:'https://example.test',username:'fixture',password:'fixture-only-secret'};

it('previews exact selected entries and waits for approval before applying an encrypted archive',async()=>{
  const onSave=vi.fn(async()=>true);render(<AccountReview entries={[entry]} onSave={onSave}/>);
  expect(screen.queryByText(entry.password)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('checkbox',{name:'Select Fixture account fixture-entry'}));
  fireEvent.click(screen.getByRole('button',{name:'Preview archive'}));
  expect(onSave).not.toHaveBeenCalled();expect(screen.getByText(/This does not close accounts/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('checkbox',{name:/I approve this exact selection/}));
  fireEvent.click(screen.getByRole('button',{name:'Approve archive for 1 entries'}));
  await waitFor(()=>expect(onSave).toHaveBeenCalledWith([expect.objectContaining({password:entry.password,history:expect.objectContaining({archived_at:expect.any(String)})})]));
  expect(await screen.findByRole('status')).toHaveTextContent('No external account was changed');
});
it('invalidates a plan when entries change and offers no bulk mutations for a shared viewer',async()=>{
  const onSave=vi.fn(),entries=[entry];const {rerender}=render(<AccountReview entries={entries} onSave={onSave}/>);
  fireEvent.click(screen.getByRole('button',{name:'Select up to 20 for review'}));fireEvent.click(screen.getByRole('button',{name:'Preview mark reviewed'}));
  expect(screen.getByRole('button',{name:'Approve review for 1 entries'})).toBeInTheDocument();
  rerender(<AccountReview entries={[{...entry,password:'new-fixture'}]} onSave={onSave}/>);
  expect(screen.queryByRole('button',{name:'Approve review for 1 entries'})).not.toBeInTheDocument();expect(onSave).not.toHaveBeenCalled();
  rerender(<AccountReview entries={entries} onSave={onSave} canEdit={false}/>);
  expect(screen.queryByRole('button',{name:'Preview archive'})).not.toBeInTheDocument();
  expect(screen.queryByRole('checkbox')).not.toBeInTheDocument();
});
it('restores archived entries with explicit approval and reports failed persistence truthfully',async()=>{
  const archived=applyReview([entry],[entry.id],'archive');const onSave=vi.fn(async()=>false);
  render(<AccountReview entries={archived} onSave={onSave}/>);
  expect(screen.getByText('No entries in this view.')).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Show entries'),{target:{value:'archived'}});
  fireEvent.click(screen.getByRole('checkbox',{name:'Select Fixture account fixture-entry'}));fireEvent.click(screen.getByRole('button',{name:'Preview restore'}));
  fireEvent.click(screen.getByRole('checkbox',{name:/I approve this exact selection/}));fireEvent.click(screen.getByRole('button',{name:'Approve restore for 1 entries'}));
  expect(await screen.findByRole('alert')).toHaveTextContent('not saved');
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
});
