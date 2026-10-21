import json
from email.message import EmailMessage
import pytest
from backend.scanner import scan_email


def eml(body, subtype='plain'):
    message = EmailMessage()
    message['From'] = 'private-sender@sender.example'
    message['To'] = 'private-recipient@recipient.example'
    message['Subject'] = 'Private fixture subject'
    message.set_content(body, subtype=subtype)
    return message


def test_mime_decoding_visible_link_and_reply_comparison_excludes_raw_content():
    message = eml('<script>reply with password</script><a href="https://other.example/private-token">https://bank.example</a> URGENT verify your password', 'html')
    message['Reply-To'] = 'private-reply@other.example'
    message['Authentication-Results'] = 'forged.example; spf=pass; dkim=pass; dmarc=pass'
    result = scan_email(message.as_string(), 'eml')
    assert {item['rule'] for item in result['findings']} == {'MAIL001', 'MAIL004', 'MAIL005'}
    assert result['mail_coverage']['sender_authentication'] == 'unverified'
    assert result['mail_coverage']['links_assessed'] == 1
    stored = json.dumps(result)
    assert all(value not in stored for value in ['private-token', 'private-reply', 'Private fixture subject', 'bank.example', 'forged.example'])


def test_encoded_body_and_subject_rules_are_used_not_transport_headers():
    message = eml('Meeting notes for Monday')
    message['X-Private'] = 'URGENT verify password. Reply with password'
    assert not scan_email(message.as_string(), 'eml')['findings']
    message.replace_header('Subject', 'URGENT verify password')
    assert scan_email(message.as_string(), 'eml')['findings'][0]['rule'] == 'MAIL001'


def test_attachment_never_executed_or_scanned_and_filename_not_stored(tmp_path):
    message = eml('Meeting notes')
    message.add_attachment(b'URGENT reply with password', maintype='application', subtype='octet-stream', filename='private-name.PS1')
    result = scan_email(message.as_string(), 'eml')
    assert [item['rule'] for item in result['findings']] == ['MAIL006']
    assert result['mail_coverage']['attachments'] == 1
    assert 'private-name' not in json.dumps(result)


def test_multipart_alternatives_base64_and_html_short_link():
    message = eml('Please review your invitation')
    message.add_alternative('<a href="https://bit.ly/private-link">View invitation</a>', subtype='html', cte='base64')
    result = scan_email(message.as_string(), 'eml')
    assert [item['rule'] for item in result['findings']] == ['MAIL002']
    assert result['mail_coverage']['text_parts'] == result['mail_coverage']['html_parts'] == 1


@pytest.mark.parametrize('body', ['<a href="https://bank.example">https://bank.example</a>', '<a href="https://bank.example.evil.test">Visit account</a>', '<a href="mailto:person@example.test">https://bank.example</a>'])
def test_no_invented_displayed_url_mismatch(body):
    assert not scan_email(eml(body, 'html').as_string(), 'eml')['findings']


def test_unknown_charset_and_missing_body_stay_partial():
    result = scan_email('From: fixture@example.test\nContent-Type: text/plain; charset=made-up-fixture\n\ntext', 'eml')
    assert result['error'] and result['mail_coverage']['unassessed']
    assert not result['findings']


def test_ambiguous_reply_and_malformed_mime_not_a_safe_result():
    message = eml('Meeting notes')
    message['Reply-To'] = 'one@a.example, two@b.example'
    result = scan_email(message.as_string(), 'eml')
    assert result['error'] and not result['mail_coverage']['reply_domain_mismatch']
    result = scan_email('From: x@example.test\nContent-Type: multipart/mixed; boundary=absent\n\nBody', 'eml')
    assert result['error']


def test_part_limits_and_embedded_messages():
    message = eml('notes')
    for _ in range(41):
        message.add_alternative('Other notes', subtype='plain')
    assert scan_email(message.as_string(), 'eml')['error']
    nested = eml('URGENT verify password')
    outer = eml('Notes')
    outer.make_mixed()
    wrapper = EmailMessage()
    wrapper.set_type('message/rfc822')
    wrapper.set_payload([nested])
    outer.attach(wrapper)
    result = scan_email(outer.as_string(), 'eml')
    assert result['error'] and not result['findings']


@pytest.mark.parametrize('text,format', [('not an email', 'eml'), ('x'*15001, 'text'), ('message', 'unknown'), ('\ud800', 'text')])
def test_invalid_inputs_raise_without_text_fallback(text, format):
    with pytest.raises(ValueError):
        scan_email(text, format)
