import os
import re


def safe_error(exc):
    """Keep actionable exception details while redacting configured credentials."""
    parts, seen = [], set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        parts.append(f'{type(exc).__name__}: {exc}')
        exc = exc.__cause__ or (None if exc.__suppress_context__ else exc.__context__)
        if isinstance(exc, RuntimeError) and str(exc) == 'no running event loop':
            exc = None
    text = ' <- '.join(parts)
    for key, value in os.environ.items():
        if value and re.search(r'(?:^|_)(?:API_KEY|ACCESS_TOKEN|AUTH_TOKEN|TOKEN|SECRET|PASSWORD|PRIVATE_KEY|CLIENT_SECRET)$', key.upper()):
            text = text.replace(value, '[REDACTED]')
    text = re.sub(r'\b(?:gsk_|sk-)[A-Za-z0-9_-]+', '[REDACTED]', text)
    text = re.sub(r'(?i)Bearer\s+\S+', 'Bearer [REDACTED]', text)
    return text[:2500]
