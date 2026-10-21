"""Bounded local message extraction. No remote resources or sender verification."""
from email import policy
from email.parser import Parser
from email.utils import getaddresses
from html.parser import HTMLParser
from urllib.parse import urlsplit
import re

LIMITS = ('Text indicators and MIME/header observations only; not the assign-3 trained classifier or an inbox filter. '
          'Sender identity, SPF/DKIM/DMARC, attachment contents and remote destinations are unverified. '
          'Header claims can be forged. No links or remote images are opened. No indicators does not mean safe.')


def host(value):
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {'http', 'https'}:
            return None
        domain = parsed.hostname
        return domain.lower().rstrip('.').encode('idna').decode('ascii') if domain else None
    except (ValueError, UnicodeError):
        return None


class VisibleHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.links, self.anchor = [], [], None
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in {'script', 'style', 'template'}:
            self.hidden += 1
        if tag == 'a' and not self.hidden:
            if self.anchor is not None:
                self.finish_anchor()
            self.anchor = [dict(attrs).get('href', ''), []]

    def handle_endtag(self, tag):
        if tag in {'script', 'style', 'template'}:
            self.hidden = max(0, self.hidden - 1)
        if tag == 'a':
            self.finish_anchor()

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)
            if self.anchor is not None:
                self.anchor[1].append(data)

    def finish_anchor(self):
        if self.anchor is not None:
            self.links.append((self.anchor[0], ''.join(self.anchor[1]).strip()))
            self.anchor = None


def extract(text, format='text'):
    if format not in {'text', 'eml'}:
        raise ValueError('Select message text or an RFC 822 .eml message.')
    try:
        if len(text.encode('utf-8')) > 60000 or len(text) > 15000:
            raise ValueError('Email must be at most 15,000 characters and 60 KB.')
    except UnicodeError as exc:
        raise ValueError('Message encoding is invalid.') from exc
    coverage = dict(format=format, text_parts=0, html_parts=0, attachments=0,
                    executable_attachments=0, links_assessed=0, unassessed=[],
                    sender_authentication='unverified', reply_domain_mismatch=False,
                    displayed_link_mismatches=0)
    if format == 'text':
        return text, [], coverage
    try:
        message = Parser(policy=policy.default).parsestr(text)
        if not message.keys() or '\n\n' not in text.replace('\r\n', '\n'):
            raise ValueError('Submit an RFC 822 message with headers and a blank line before the body.')
        bodies, links = [], []
        subject = str(message.get('Subject', ''))
        def domains(header):
            addresses = getaddresses([str(value) for value in message.get_all(header, [])])
            return {address.rsplit('@', 1)[1].lower().rstrip('.').encode('idna').decode('ascii')
                    for _, address in addresses if address.count('@') == 1 and address.rsplit('@', 1)[1]}
        sender, reply = domains('From'), domains('Reply-To')
        if len(sender) == 1 and len(reply) == 1:
            coverage['reply_domain_mismatch'] = sender != reply
        elif message.get('Reply-To'):
            coverage['unassessed'].append('Reply address comparison unavailable or ambiguous.')
        pending, visited = [(message, 0)], 0
        while pending:
            part, depth = pending.pop()
            visited += 1
            if visited > 40 or depth > 8:
                coverage['unassessed'].append('MIME part or nesting limit reached.')
                break
            if part.defects:
                coverage['unassessed'].append('Malformed MIME structure encountered.')
            attachment = part.get_content_disposition() == 'attachment' or part.get_filename() is not None
            if attachment:
                coverage['attachments'] += 1
                filename = part.get_filename() or ''
                if re.search(r'\.(exe|com|scr|bat|cmd|ps1|js|vbs|msi|lnk|hta)\s*$', filename, re.I):
                    coverage['executable_attachments'] += 1
                continue
            if part.get_content_type() == 'message/rfc822':
                coverage['unassessed'].append('Embedded messages were not assessed.')
                continue
            if part.is_multipart():
                pending.extend((child, depth + 1) for child in reversed(part.get_payload()))
                continue
            mime = part.get_content_type()
            if mime not in {'text/plain', 'text/html'}:
                coverage['unassessed'].append('Non-text inline content was not assessed.')
                continue
            try:
                body = part.get_content(errors='strict')
            except (LookupError, UnicodeError, ValueError, KeyError):
                coverage['unassessed'].append('A text part could not be decoded.')
                continue
            if part.defects:
                coverage['unassessed'].append('Malformed text encoding encountered.')
            if mime == 'text/html':
                html = VisibleHTML()
                html.feed(body)
                html.finish_anchor()
                bodies.append(' '.join(html.text))
                links.extend(html.links)
                coverage['html_parts'] += 1
            else:
                bodies.append(body)
                coverage['text_parts'] += 1
        if len(links) > 30:
            coverage['unassessed'].append('Only the first 30 HTML links were assessed.')
        links = links[:30]
        coverage['links_assessed'] = sum(host(href) is not None for href, _ in links)
        coverage['displayed_link_mismatches'] = sum(bool(host(label) and host(href) and host(label) != host(href)) for href, label in links)
        if not bodies:
            coverage['unassessed'].append('No decodable top-level text body was assessed.')
        coverage['unassessed'] = list(dict.fromkeys(coverage['unassessed']))
        return '\n'.join([subject, *bodies]), [href for href, _ in links], coverage
    except (RecursionError, TypeError, IndexError, AttributeError, UnicodeError) as exc:
        raise ValueError('Message could not be parsed within the supported MIME format.') from exc
