"""Bounded, evidence-first checks; submitted source and email are never executed."""
import ast
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from urllib.parse import urlsplit

import httpx

RULES = {
    'HOST001':('low','Windows firewall profile disabled','CWE-693','Review whether this profile is used and restore the intended firewall configuration with the device administrator. No rule or public-exposure assessment was performed.','https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile'),
    'HOST002':('unknown','Microsoft Defender protection requires review','CWE-693','Check the active antivirus product and Defender operating mode locally. A disabled Defender service does not prove the device has no antivirus.','https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus'),
    'HOST003':('medium','System-drive BitLocker protection is off','CWE-311','Review encryption and suspension state with the device owner. Verify recovery arrangements before changing encryption settings. No recovery keys were collected.','https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide'),
    'UPD001':('medium','Cached security/critical updates pending','Not assessed','Open Windows Update on the assessed computer, refresh its catalog, review and install approved updates, then recheck. Cached counts alone do not establish patch exposure.','https://support.microsoft.com/windows/windows-update-faq-8a903416-6f45-0718-f5c7-375e92dddeb2'),
    'UPD002':('low','Windows Update restart pending','Not assessed','Plan a restart with the device owner after saving work and checking service availability. Verify update status again afterward. No restart is performed by SentinelOps.','https://support.microsoft.com/windows/windows-update-faq-8a903416-6f45-0718-f5c7-375e92dddeb2'),
    "PY001": ("high", "Fast password hashing", "CWE-916", "Use Argon2id or scrypt with a unique salt and a calibrated work factor.", "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"),
    "PY002": ("high", "Predictable security token", "CWE-338", "Use secrets.token_urlsafe; expire and consume reset tokens once.", "https://docs.python.org/3/library/secrets.html"),
    "PY003": ("high", "TLS verification disabled", "CWE-295", "Enable certificate verification and configure a trusted CA bundle.", "https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification"),
    "PY004": ("high", "Shell execution enabled", "CWE-78", "Use a fixed executable and an argument array with shell=False; review input origin.", "https://docs.python.org/3/library/subprocess.html#security-considerations"),
    "PY005": ("medium", "Debug mode explicitly enabled", "CWE-489", "Disable debug mode for deployed environments and verify release configuration.", "https://flask.palletsprojects.com/en/stable/debugging/"),
    "PY006": ("high", "Dynamic code evaluation", "CWE-95", "Replace eval/exec with a bounded parser and allowed operations; review input origin.", "https://docs.python.org/3/library/functions.html#eval"),
    "PY007": ("medium", "Cookie protection disabled", "CWE-614", "Enable secure and HttpOnly cookies on HTTPS and choose an appropriate SameSite policy.", "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"),
    "PY008": ("high", "Credential-like source literal", "CWE-798", "Remove the literal and rotate the credential if real. Review repository history.", "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"),
    "DEP001": ("unknown", "Dependency advisory match", "CWE-1395", "Review the OSV advisory, upgrade to a fixed compatible version and test. Reachability is not established.", "https://osv.dev/"),
    "WEB001": ("medium", "Content Security Policy absent", "CWE-693", "Define and test a restrictive Content-Security-Policy for HTML responses.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"),
    "WEB002": ("medium", "HSTS absent", "CWE-319", "After validating HTTPS across the domain, configure Strict-Transport-Security.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"),
    "WEB003": ("low", "MIME sniffing protection absent", "CWE-693", "Set X-Content-Type-Options: nosniff on responses.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"),
    "WEB004": ("low", "Framing policy absent", "CWE-1021", "Set CSP frame-ancestors or X-Frame-Options for pages that should not be embedded.", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"),
    "WEB005": ("low", "Technology header disclosed", "CWE-200", "Consider removing version-bearing Server/X-Powered-By headers. Disclosure alone does not prove a vulnerability.", "https://owasp.org/www-project-web-security-testing-guide/"),
    "MAIL001": ("medium", "Urgency and credential request", "CWE-451", "Verify the request with the sender through a previously trusted channel. Do not use the message link.", "https://www.cisa.gov/secure-our-world/recognize-and-report-phishing"),
    "MAIL002": ("medium", "Link obscures destination", "CWE-451", "Inspect the destination independently. Shortened links and IP URLs are indicators, not proof of phishing.", "https://www.cisa.gov/secure-our-world/recognize-and-report-phishing"),
    "MAIL003": ("high", "Sensitive data request", "CWE-359", "Do not reply with credentials or financial information; verify through an established channel.", "https://www.cisa.gov/secure-our-world/recognize-and-report-phishing"),
    "MAIL004": ("low", "Reply address domain differs", "CWE-451", "Verify reply routing through an established channel. Different domains can be legitimate; this is not proof of impersonation.", "https://www.cisa.gov/secure-our-world/recognize-and-report-phishing"),
    "MAIL005": ("medium", "Displayed link host differs from target", "CWE-451", "Open the known service independently instead of using the message link. A host mismatch needs review but does not establish maliciousness.", "https://www.cisa.gov/secure-our-world/recognize-and-report-phishing"),
    "MAIL006": ("unknown", "Executable attachment requires review", "CWE-434", "Do not execute unexpected attachments. Verify with the sender and use your endpoint security tools; no attachment content scan was performed.", "https://www.cisa.gov/secure-our-world/recognize-and-report-phishing"),
    "PORT001": ("unknown", "Local TCP listener requires review", "CWE-16", "Identify the owning application locally. Verify necessity, authentication, binding interface and firewall rules before changing anything. Open does not mean vulnerable or publicly reachable.", "https://www.cisa.gov/resources-tools/resources/securing-network-infrastructure-devices"),
}
PY_LIMITS = "Eight Python AST rules, one submitted file; no data flow, runtime, reachability, JavaScript or infrastructure coverage. No findings does not establish security."


def finding(rule, line=0, evidence="", confidence="medium", **extra):
    severity, title, cwe, guidance, reference = RULES[rule]
    return dict(rule=rule, title=title, severity=severity, cwe=cwe, guidance=guidance, reference=reference, line=line, evidence=evidence, confidence=confidence, **extra)


def scan_python(source):
    if len(source.encode()) > 120_000:
        raise ValueError("Source must be at most 120 KB.")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError) as e:
        raise ValueError("Python parsing failed; no assessment completed.") from e
    aliases = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                aliases[a.asname or a.name] = a.name
        if isinstance(n, ast.ImportFrom) and n.module:
            for a in n.names:
                aliases[a.asname or a.name] = f"{n.module}.{a.name}"

    def name(n):
        if isinstance(n, ast.Name):
            return aliases.get(n.id, n.id)
        if isinstance(n, ast.Attribute):
            return name(n.value) + "." + n.attr
        return ""

    items = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            call = name(n.func)
            keywords = {k.arg: k.value.value for k in n.keywords if isinstance(k.value, ast.Constant)}
            if call in {"hashlib.md5", "hashlib.sha1", "hashlib.sha256", "hashlib.sha512"} and any(isinstance(v, ast.Name) and re.search("password|passwd|passphrase", v.id, re.I) for arg in n.args for v in ast.walk(arg)):
                items.append(finding("PY001", n.lineno, "Fast hashlib digest receives a password-named input."))
            if call.startswith("random.") and call.split(".")[-1] in {"choice", "choices", "randint", "randrange", "getrandbits", "random"}:
                contexts = [x for x in ast.walk(tree) if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Assign)) and x.lineno <= n.lineno <= x.end_lineno]
                ids = [x.name for x in contexts if isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef))]
                ids += [v.id for x in contexts if isinstance(x, ast.Assign) for t in x.targets for v in ast.walk(t) if isinstance(v, ast.Name)]
                if any(re.search("token|password|secret|nonce|otp", v, re.I) for v in ids):
                    items.append(finding("PY002", n.lineno, "random used in a security-named context; heuristic, not data-flow proof."))
            if call.startswith(("requests.", "httpx.")) and keywords.get("verify") is False:
                items.append(finding("PY003", n.lineno, "HTTP call explicitly disables certificate verification.", "high"))
            if call.startswith("subprocess.") and keywords.get("shell") is True:
                items.append(finding("PY004", n.lineno, "subprocess enables shell=True; input origin requires review."))
            if call.endswith(".run") and keywords.get("debug") is True:
                items.append(finding("PY005", n.lineno, "Run call explicitly enables debug=True."))
            if call in {"eval", "exec", "builtins.eval", "builtins.exec"}:
                items.append(finding("PY006", n.lineno, "Dynamic evaluation found; input origin requires review."))
            if call.endswith(".set_cookie") and any(keywords.get(k) is False for k in ("secure", "httponly")):
                items.append(finding("PY007", n.lineno, "Cookie call explicitly disables a protection."))
        if isinstance(n, (ast.Assign, ast.AnnAssign)):
            for target in n.targets if isinstance(n, ast.Assign) else [n.target]:
                identifier, value = name(target), n.value
                if identifier.upper() in {"SESSION_COOKIE_SECURE", "SESSION_COOKIE_HTTPONLY"} and isinstance(value, ast.Constant) and value.value is False:
                    items.append(finding("PY007", n.lineno, "Session cookie configuration disables a protection.", "high"))
                if re.search(r"(^|_)(api_key|secret_key|password|passwd|access_token)$", identifier, re.I) and isinstance(value, ast.Constant) and isinstance(value.value, str) and len(value.value) >= 8:
                    items.append(finding("PY008", n.lineno, "Credential-named assignment has a string literal. Value redacted."))
    return dict(findings=list({(x["rule"], x["line"]): x for x in items}.values()), source_digest=hashlib.sha256(source.encode()).hexdigest(), rules_checked=list(RULES)[:8], limits=PY_LIMITS)


def scan_email(text, format='text'):
    from .mail_analysis import extract, LIMITS
    message_digest = hashlib.sha256(text.encode('utf-8', errors='surrogatepass')).hexdigest()
    text, html_links, coverage = extract(text, format)
    lowered = text.lower()
    urgent = bool(re.search(r"\b(urgent|immediately|suspended|final notice|action required)\b", lowered))
    credential = bool(re.search(r"\b(verify|password|credentials|login|sign in|reset)\b", lowered))
    sensitive = bool(re.search(r"\b(send|reply|provide|share)\b.{0,90}\b(password|otp|bank details|card number|passport|ssn)\b", lowered))
    text_links = re.findall(r"https?://[^\s<>\"']+", text)
    coverage['text_links_assessed'] = min(30, len(text_links))
    if len(text_links) > 30:
        coverage['unassessed'].append('Only the first 30 text links were assessed.')
    urls = text_links[:30] + html_links
    obscured = False
    for url in urls:
        try:
            host = urlsplit(url).hostname or ""
            obscured |= host.lower() in {"bit.ly", "tinyurl.com", "t.co", "is.gd"} or bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host)) or "@" in urlsplit(url).netloc
        except ValueError:
            obscured = True
    items = []
    if urgent and credential:
        items.append(finding("MAIL001", evidence="Urgency language and an account/credential request occur together."))
    if obscured:
        items.append(finding("MAIL002", evidence="A shortened, numeric-host or userinfo-bearing URL was found. URL redacted."))
    if sensitive:
        items.append(finding("MAIL003", evidence="A request to share credentials or sensitive identifiers was found."))
    if coverage['reply_domain_mismatch']:
        items.append(finding('MAIL004', evidence='The single From and Reply-To address domains differ. Addresses redacted; legitimate reply routing can differ.', confidence='low'))
    if coverage['displayed_link_mismatches']:
        items.append(finding('MAIL005', evidence='A visible HTTP(S) URL names a different host from its HTML link target. Destinations redacted; legitimate redirects may differ.'))
    if coverage['executable_attachments']:
        items.append(finding('MAIL006', evidence='An attachment filename has an executable or script extension. Filename and contents omitted; contents were not scanned.', confidence='low'))
    result = dict(findings=items, signals={"urgency": urgent, "credential_context": credential, "obscured_link": obscured, "sensitive_request": sensitive, "links_count": len(urls)}, outcome="Review recommended" if items else "No listed indicators found", message_digest=message_digest, mail_coverage=coverage, limits=LIMITS)
    if coverage['unassessed']:
        result['error'] = 'Message coverage is incomplete; inspect unassessed content.'
    return result


def parse_dependencies(text, format):
    from .dependency_inventory import inventory
    parsed=inventory(text,format)
    return parsed['packages'],parsed['skipped']


def scan_dependencies(text, format, transport=None, selection=None):
    from .dependency_inventory import inventory,apply_coverage
    scope=inventory(text,format,selection)
    return apply_coverage(scan_watch(scope['packages'],transport),scope)


def scan_watch(packages,transport=None):
    """Bounded OSV batches; preserve completed coverage when later batches fail."""
    from .dependency_inventory import MAX_PACKAGES,pin
    if not isinstance(packages,list) or len(packages)>MAX_PACKAGES:raise ValueError('Use at most 500 exact pins.')
    for package in packages:pin(package['ecosystem'],package['name'],package['version'])
    items,checked,error=[],[],None
    deadline=time.monotonic()+60;received=0
    with httpx.Client(timeout=8,transport=transport,follow_redirects=False) as client:
        for offset in range(0,len(packages),50):
            batch=packages[offset:offset+50]
            try:
                if time.monotonic()>=deadline:raise ValueError()
                queries=[{'package':{'ecosystem':p['ecosystem'],'name':p['name']},'version':p['version']} for p in batch]
                with client.stream('POST','https://api.osv.dev/v1/querybatch',json={'queries':queries},timeout=min(8,max(.1,deadline-time.monotonic()))) as response:
                    response.raise_for_status();raw=bytearray()
                    for chunk in response.iter_bytes(chunk_size=16384):
                        raw.extend(chunk);received+=len(chunk)
                        if len(raw)>1000000 or received>4000000 or time.monotonic()>deadline:raise ValueError()
                value=json.loads(raw)
                if not isinstance(value,dict) or not isinstance(value.get('results'),list) or len(value['results'])!=len(batch):raise ValueError()
                for package,result in zip(batch,value['results']):
                    if not isinstance(result,dict) or not isinstance(result.get('vulns',[]),list) or len(result.get('vulns',[]))>100:
                        error='OSV returned unsupported or over-limit results. Coverage is incomplete.';continue
                    current=[];seen=set()
                    for vuln in result.get('vulns',[]):
                        advisory=vuln.get('id') if isinstance(vuln,dict) else None
                        if not isinstance(advisory,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}',advisory) or advisory in seen:raise ValueError()
                        seen.add(advisory)
                        current.append(finding('DEP001',package['line'],f"OSV batch matches {package['ecosystem']} {package['name']}@{package['version']} to {advisory}.",'high',advisory=advisory,package=package))
                        current[-1]['reference']='https://osv.dev/vulnerability/'+advisory
                    if len(items)+len(current)>200:
                        error='OSV advisory coverage exceeded this check limit; review a narrower inventory.';continue
                    items.extend(current)
                    if result.get('next_page_token'):error='OSV results were paginated. Returned matches are recorded, but coverage is incomplete.'
                    else:checked.append(package)
            except (httpx.HTTPError,ValueError,TypeError,AttributeError):
                error='OSV request failed or returned unsupported data. Coverage is incomplete; no safe result was inferred.'
                break
    from .advisories import enrich
    items,detail_coverage=enrich(items,transport)
    return dict(findings=items,packages=packages,checked=checked,skipped=[],error=error,advisory_details=detail_coverage,limits='OSV matches for selected exact PyPI/npm versions only; at most 500 pins in batches of 50 with a 60-second batch budget and 200 recorded matches. Up to 20 detail requests group aliases and calculate valid CVSS base ratings. Package, source-exclusion, detail and severity coverage are separate; unavailable ratings remain unknown. No package installation, runtime graph resolution or exploit reachability. Missing matches do not certify safety.' if packages else 'No exact pins were supplied; no packages were assessed.')


def inspect_headers(headers, status=200):
    headers = {k.lower(): v for k, v in headers.items()}
    checks = [("content-security-policy", "WEB001"), ("strict-transport-security", "WEB002"), ("x-content-type-options", "WEB003")]
    items = [finding(rule, evidence=f"{header} absent from the assessed HTTPS response.") for header, rule in checks if not headers.get(header)]
    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", "").lower():
        items.append(finding("WEB004", evidence="Neither X-Frame-Options nor CSP frame-ancestors is present."))
    if headers.get("server") or headers.get("x-powered-by"):
        items.append(finding("WEB005", evidence="Server or X-Powered-By header is present; value omitted."))
    return dict(findings=items, http_status=status, present_headers=[k for k in headers if k in {x[0] for x in checks} | {"x-frame-options"}], limits="One HTTPS HEAD response on port 443, no redirects. Header presence is not policy correctness. No crawling, port sweep, exploitation, banner-to-CVE claims or authenticated-page coverage.")


def validate_host(host):
    host = host.lower().strip().rstrip(".")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host):
        raise ValueError("Enter an exact public DNS hostname without a scheme, path or port.")
    return host


def scan_web(host, allowed):
    host = validate_host(host)
    if host not in allowed:
        raise ValueError("Host is not in the server operator's SCAN_HOSTS allowlist.")
    addresses = list({info[4][0] for info in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    if not addresses or any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("Target must resolve exclusively to public addresses.")
    # Pin the vetted IP while retaining certificate verification and SNI. No second DNS lookup.
    class PinnedConnection(http.client.HTTPSConnection):
        def connect(self):
            raw = socket.create_connection((addresses[0], 443), timeout=6)
            try:
                self.sock = self._context.wrap_socket(raw, server_hostname=host)
            except BaseException:
                raw.close()
                raise
    connection = PinnedConnection(host, timeout=6, context=ssl.create_default_context())
    try:
        connection.request("HEAD", "/", headers={"User-Agent": "SentinelOps/0.1 authorized-assessment", "Connection": "close"})
        response = connection.getresponse()
        return inspect_headers(dict(response.getheaders()), response.status)
    finally:
        connection.close()
