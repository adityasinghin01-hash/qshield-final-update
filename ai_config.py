"""Shared backend AI settings. Reading configuration does not authenticate a key."""
from __future__ import annotations
import ipaddress
import math
import os
from pathlib import Path
import re
import shlex
from urllib.parse import urlsplit

CURRENT_DIR = Path(__file__).resolve().parent


def load_dotenv_if_present(env_path=None):
    path = Path(env_path) if env_path is not None else CURRENT_DIR / '.env'
    if not path.is_file():
        return
    try:
        lines = path.read_text(encoding='utf-8-sig').splitlines()
    except (OSError, UnicodeError):
        raise ValueError('Cannot read the project .env file; check its permissions and UTF-8 encoding.') from None
    for line in lines:
        line = line.strip()
        if line.startswith('export '):
            line = line[7:].lstrip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.strip()
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key):
            continue
        try:
            parts = shlex.split(value, comments=True, posix=True)
        except ValueError:
            raise ValueError('Invalid quoting in .env; check the entry named '+key+'.') from None
        if len(parts) > 1:
            raise ValueError('Quote values containing spaces in .env; check '+key+'.')
        os.environ.setdefault(key, parts[0] if parts else '')


def validate_base_url(value):
    try:
        url = urlsplit(value)
        port = url.port
        host = url.hostname
        loopback = host == 'localhost'
        try:
            loopback = loopback or ipaddress.ip_address(host).is_loopback
        except (ValueError, TypeError):
            pass
        if (not host or url.username is not None or url.password is not None
                or url.query or url.fragment or (port is not None and port == 0)
                or any(c.isspace() or ord(c) < 32 for c in value)
                or (url.scheme != 'https' and not (url.scheme == 'http' and loopback))):
            raise ValueError
    except ValueError:
        raise ValueError('AI base URL must use HTTPS (HTTP only on loopback), without credentials, query or fragment.') from None
    return value.rstrip('/')


def get_provider_config():
    load_dotenv_if_present()
    provider = os.environ.get('QSHIELD_AI_PROVIDER', 'openai').strip().lower()
    if provider not in ('openai','openai-compatible','agentrouter','mock','offline'):
        raise ValueError('Unsupported QSHIELD_AI_PROVIDER; use openai, openai-compatible, agentrouter or mock.')
    explicit_base = (os.environ.get('QSHIELD_AI_BASE_URL','') or os.environ.get('OPENAI_BASE_URL','')).strip()
    if provider in ('agentrouter','openai-compatible') and not explicit_base:
        raise ValueError('Set QSHIELD_AI_BASE_URL to the base URL from your provider dashboard.')
    base = validate_base_url(explicit_base or 'https://api.openai.com/v1')
    try:
        timeout = float(os.environ.get('QSHIELD_AI_TIMEOUT','30'))
        if not math.isfinite(timeout) or not 1 <= timeout <= 120:
            raise ValueError
    except ValueError:
        raise ValueError('QSHIELD_AI_TIMEOUT must be between 1 and 120 seconds.') from None
    api = os.environ.get('QSHIELD_AI_API','').strip() or ('chat_completions' if provider in ('agentrouter','openai-compatible') else 'responses')
    if api not in ('responses','chat_completions'):
        raise ValueError('QSHIELD_AI_API must be responses or chat_completions.')
    return dict(api_key=(os.environ.get('OPENAI_API_KEY','') or os.environ.get('QSHIELD_AI_API_KEY','')).strip(),
                provider=provider, model=(os.environ.get('QSHIELD_AI_MODEL','') or os.environ.get('OPENAI_MODEL','') or 'gpt-4o-mini').strip(),
                base_url=base, timeout=timeout, api=api)
