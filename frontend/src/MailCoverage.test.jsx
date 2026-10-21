import {render,screen} from '@testing-library/react';
import {it,expect} from 'vitest';
import MailCoverage from './MailCoverage';
it('shows unverified authentication, excluded attachments and incomplete decoding without inventing safety',()=>{
  render(<MailCoverage coverage={{format:'eml',text_parts:1,html_parts:1,attachments:2,executable_attachments:1,links_assessed:3,displayed_link_mismatches:1,reply_domain_mismatch:true,unassessed:['A text part could not be decoded.']}}/>);
  expect(screen.getByText(/sender authentication: unverified/)).toBeInTheDocument();
  expect(screen.getByText(/2 attachments excluded/)).toBeInTheDocument();
  expect(screen.getByText('A text part could not be decoded.')).toBeInTheDocument();
  expect(screen.getByText(/No indicators does not mean safe/)).toBeInTheDocument();
});
it('does not add MIME coverage to historical scans without it',()=>{
  const {container}=render(<MailCoverage/>);expect(container).toBeEmptyDOMElement();
});
