import {expect,it} from 'vitest';
import {render,screen} from '@testing-library/react';
import AdvisorySeverity from './AdvisorySeverity';

const rating={advisory:'GHSA-fixture',version:'3.1',base_score:9.8,rating:'critical',declared_source:'CNA',vector:'CVSS:3.1/AV:N',reported_vector:'CVSS:3.1/AV:N/E:U'};

it('keeps legacy or unavailable dependency ratings unknown and leaves other finding kinds alone',()=>{
  const {rerender,container}=render(<AdvisorySeverity finding={{rule:'PY001'}}/>);
  expect(container).toBeEmptyDOMElement();
  rerender(<AdvisorySeverity finding={{rule:'DEP001'}}/>);
  expect(screen.getByRole('status')).toHaveTextContent('match is retained');
  expect(screen.getByRole('status')).toHaveTextContent('does not mean low risk');
});

it('shows source, version, base vector and incomplete coverage without an exploitability claim',()=>{
  render(<AdvisorySeverity finding={{rule:'DEP001',severity_assessment:{selected:rating,ratings:[rating],status:'partial',scored_advisories:1,total_advisories:2,ignored_ratings:1,truncated:true}}}/>);
  const region=screen.getByRole('region',{name:'Advisory severity'});
  expect(region).toHaveTextContent('9.8 / 10 · critical · CVSS 3.1 base');
  expect(region).toHaveTextContent('1/2 matched advisory records');
  expect(region).toHaveTextContent('does not measure exposure or prove exploitability');
  expect(region).toHaveTextContent('source declared by record: CNA');
  expect(region).toHaveTextContent('Optional threat, temporal or environmental metrics are excluded');
  expect(region).toHaveTextContent('1 invalid or ambiguous');
  expect(region).toHaveTextContent('partial view');
  expect(screen.getByRole('link',{name:'GHSA-fixture'})).toHaveAttribute('href','https://osv.dev/vulnerability/GHSA-fixture');
});

it('shows zero base score without hiding the match or inventing rating provenance',()=>{
  const zero={...rating,base_score:0,rating:'none',declared_source:null,reported_vector:rating.vector};
  render(<AdvisorySeverity finding={{rule:'DEP001',severity_assessment:{selected:zero,ratings:[zero],status:'available',scored_advisories:1,total_advisories:1,ignored_ratings:0,truncated:false}}}/>);
  expect(screen.getByRole('region')).toHaveTextContent('0.0 / 10');
  expect(screen.getByRole('region')).toHaveTextContent('No separate rating source declared');
  expect(screen.getByRole('region')).not.toHaveTextContent('incomplete');
});
