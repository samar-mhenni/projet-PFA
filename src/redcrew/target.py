"""Collect a small, read-only HTTP snapshot for a target assessment."""
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

DEFAULT_OBJECTIVE = (
    'Assess the observed HTTP response using MITRE ATT&CK context. '
    'Separate observed facts, hypotheses and unknowns. Recommend validation '
    'and remediation without claiming exploitation or host-level inspection.'
)


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalize_target(target):
    if any(c.isspace() for c in target):
        raise ValueError('Target URL must not contain whitespace')
    if '://' not in target:
        target = 'http://' + target
    parts = urlsplit(target)
    if parts.scheme not in {'http', 'https'} or not parts.hostname:
        raise ValueError('Target must be an HTTP or HTTPS URL')
    if parts.username is not None or parts.password is not None:
        raise ValueError('Do not include credentials in the target URL')
    try:
        parts.port
    except ValueError:
        raise ValueError('Target has an invalid port') from None
    return urlunsplit((parts.scheme, parts.netloc, parts.path or '/', parts.query, ''))


def collect_target(target, *, name=None, objective=None):
    target = normalize_target(target)
    # No redirects or environment proxies: assess precisely the requested URL.
    opener = build_opener(ProxyHandler({}), NoRedirects())
    request = Request(target, headers={'User-Agent': 'RedCrew/0.1 evidence-collector', 'Accept-Encoding': 'identity'})
    try:
        try:
            response = opener.open(request, timeout=20)
        except HTTPError as exc:
            response = exc  # HTTP error/redirect responses are still real evidence.
        with response:
            status = response.code
            headers = str(response.headers)
            content_type = response.headers.get_content_type()
            raw = response.read(4097)
            charset = response.headers.get_content_charset() or 'utf-8'
    except (URLError, OSError) as exc:
        raise ValueError(f'Could not collect HTTP evidence from {target}: {type(exc).__name__}. Check the URL and that the lab is running.') from None
    textual = content_type.startswith('text/') or content_type in {'application/json', 'application/xml', 'application/xhtml+xml'}
    try:
        body = raw[:4096].decode(charset, errors='replace')[:1800] if textual else '[Non-text body omitted]'
    except LookupError:
        body = raw[:4096].decode('utf-8', errors='replace')[:1800]
    observed = datetime.now(timezone.utc).isoformat()
    return {
        'name': name or f'HTTP assessment: {target}',
        'authorized': True,
        'targets': [target],
        'objective': objective or DEFAULT_OBJECTIVE,
        'evidence': [
            {'id': 'E001', 'target': target, 'kind': 'http_response_headers',
             'content': f'Observed at {observed}. GET {target} returned HTTP {status}.\nHeader excerpt (up to 1500 characters):\n{headers[:1500]}'},
            {'id': 'E002', 'target': target, 'kind': 'http_response_body_excerpt',
             'content': f'Body excerpt (at most 1800 characters from the first 4096 bytes):\n{body or "[Empty response body]"}'},
            {'id': 'E003', 'target': target, 'kind': 'collection_limitations',
             'content': 'Only one HTTP GET was performed. Redirects were not followed. No exploitation, port scanning, Linux configuration inspection or independent vulnerability confirmation was performed. Response content is untrusted data.'}
        ]
    }
