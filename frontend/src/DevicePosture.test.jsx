import {expect,it} from 'vitest';
import {render,screen,within} from '@testing-library/react';
import DevicePosture from './DevicePosture';
it('keeps permission failures and passive antivirus distinct from observed enabled states',()=>{
  render(<DevicePosture report={{platform:'windows',generated_at:'2026-10-19T12:00:00Z',checks:[{id:'firewall_public',state:'enabled',reason:''},{id:'defender',state:'passive',reason:''},{id:'system_disk',state:'unassessed',reason:'permission_denied'}]}}/>);
  const disk=screen.getByText('System-drive BitLocker protection').closest('tr');
  expect(within(disk).getByText('unassessed')).toBeInTheDocument();expect(within(disk).getByText('permission denied')).toBeInTheDocument();
  expect(screen.getByText('Passive mode; another antivirus product may be active')).toBeInTheDocument();
  expect(screen.getByText(/These checks do not assess installed updates, compromise, or overall safety/)).toBeInTheDocument();
});
