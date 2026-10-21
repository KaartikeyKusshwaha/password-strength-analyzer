import {render,screen} from '@testing-library/react';
import {it,expect} from 'vitest';
import DeviceUpdates from './DeviceUpdates';
it('shows cached counts without implying a fully patched machine or automatic repair',()=>{
  render(<DeviceUpdates report={{platform:'windows',generated_at:'2026-10-21T00:00:00Z',cache:{state:'observed',pending:0,security:0},reboot:{state:'observed',required:false}}}/>);
  expect(screen.getByText('0 pending · 0 security/critical-classified')).toBeInTheDocument();
  expect(screen.getByText('Cache freshness unverified')).toBeInTheDocument();
  expect(screen.getByText(/Zero cached updates does not mean fully patched/)).toBeInTheDocument();
  expect(screen.getByText('Not reported required')).toBeInTheDocument();
});
it('shows denied observations explicitly',()=>{
  render(<DeviceUpdates report={{platform:'windows',generated_at:'2026-10-21T00:00:00Z',cache:{state:'unassessed',reason:'permission_denied'},reboot:{state:'unassessed',reason:'timeout'}}}/>);
  expect(screen.getByText('permission denied')).toBeInTheDocument();expect(screen.getByText('timeout')).toBeInTheDocument();
  expect(screen.queryByText(/0 pending/)).not.toBeInTheDocument();
});
