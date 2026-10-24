import {expect,it} from 'vitest';
import {render,screen,within} from '@testing-library/react';
import PortCoverage from './PortCoverage';
it('shows exactly which ports were assessed and retains unknown/failed observations as unassessed',()=>{
  render(<PortCoverage observations={[{host:'127.0.0.1',port:8110,status:'open'},{host:'127.0.0.1',port:22,status:'unassessed'},{host:'127.0.0.1',port:443,status:'closed'},{host:'127.0.0.1',port:8443,status:'unexpected'}]}/>);
  expect(screen.getByText('2/4 selected ports assessed. 2 unassessed.')).toBeInTheDocument();
  expect(within(screen.getByText('22').closest('tr')).getByText('Unassessed')).toBeInTheDocument();
  expect(within(screen.getByText('443').closest('tr')).getByText('Connection refused (closed)')).toBeInTheDocument();
  expect(screen.getByText(/do not certify safety/)).toBeInTheDocument();
});
it('does not invent coverage for an absent report or a host-posture-only report',()=>{
  const {container,rerender}=render(<PortCoverage/>);expect(container).toBeEmptyDOMElement();rerender(<PortCoverage observations={[]}/>);expect(container).toBeEmptyDOMElement();
});
