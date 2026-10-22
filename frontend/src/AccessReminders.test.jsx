import React from 'react';
import {it,expect,vi} from 'vitest';
import {render,screen,fireEvent,waitFor} from '@testing-library/react';
import AccessReminders from '../../companion/extension/AccessReminders';
const connection={id:'local',kind:'reminders',origin:'https://service.example.test',token:'x'.repeat(54)};
it('shows cached counts as status and fetches readable alerts only on request',async()=>{
 const browser={storage:{local:{get:vi.fn(async()=>({reminderConnection:connection,reminderStatus:{connectionId:'local',state:'current',count:1,checkedAt:1700000000000}})),remove:vi.fn()}}},request=vi.fn(async()=>({alerts:[{id:'lease',client:'Studio client',state:'waiting_unlock',expires_at:1900000000}],expires:1900000000}));
 render(<AccessReminders browser={browser} request={request}/>);await screen.findByRole('button',{name:'Refresh read-only reminders'});expect(request).not.toHaveBeenCalled();expect(screen.queryByText(/Studio client/)).not.toBeInTheDocument();fireEvent.click(screen.getByRole('button',{name:'Refresh read-only reminders'}));expect(await screen.findByText(/Studio client · waiting unlock/)).toBeInTheDocument();fireEvent.click(screen.getByRole('button',{name:'Disconnect reminders'}));await waitFor(()=>expect(request).toHaveBeenCalledWith(connection,'revoke'));await waitFor(()=>expect(browser.storage.local.remove).toHaveBeenCalledWith(['reminderConnection','reminderStatus']));
});
