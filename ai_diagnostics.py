"""Explicit read-only provider authentication check. Never returns credentials."""
import json
import urllib.error
import urllib.request
from ai_config import get_provider_config
from ai_provider import NoRedirect, safe_http_error


def check_ai_connection(config=None):
    result = dict(configured=False, connection_verified=False, ready=False,
                  model_available=False, http_status=None, error_code=None)
    try:
        cfg = config if config is not None else get_provider_config()
    except ValueError as error:
        return {**result, 'error_code':'invalid_configuration', 'error':str(error)}
    result.update(provider=cfg['provider'], model=cfg['model'], base_url=cfg['base_url'])
    if cfg['provider'] in ('mock','offline'):
        return {**result, 'configured':True, 'error_code':'offline_mode',
                'error':'Offline demo mode does not authenticate a live AI provider.'}
    if not cfg['api_key']:
        return {**result, 'error_code':'missing_api_key',
                'error':'Set OPENAI_API_KEY in the backend project .env or environment.'}
    result['configured'] = True
    request = urllib.request.Request(cfg['base_url']+'/models',
        headers={'Authorization':'Bearer '+cfg['api_key']}, method='GET')
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=cfg['timeout']) as response:
            raw = response.read(500_001)
        if len(raw)>500_000:
            raise ValueError
        data = json.loads(raw)
        models = data.get('data') if isinstance(data,dict) else None
        if not isinstance(models,list) or any(not isinstance(m,dict) or not isinstance(m.get('id'),str) for m in models):
            raise ValueError
        available = any(m['id']==cfg['model'] for m in models)
        result.update(connection_verified=True, http_status=200, model_available=available,
                      ready=available, model_count=len(models))
        result['note'] = 'Authentication and model listing succeeded; generation, quota and structured outputs are not yet verified.'
        if not available:
            result.update(error_code='model_not_listed',error='Authentication succeeded, but the configured model is not listed for this key.')
        return result
    except urllib.error.HTTPError as error:
        failure = safe_http_error(error)
        return {**result, 'http_status':failure.http_status, 'error_code':failure.error_code, 'error':str(failure)}
    except (urllib.error.URLError, OSError):
        return {**result, 'error_code':'connection_failed',
                'error':'Could not reach the configured provider. Check network, TLS and base URL.'}
    except (ValueError, TypeError):
        return {**result, 'http_status':200, 'error_code':'invalid_response',
                'error':'The provider did not return a valid model list. Check API endpoint compatibility.'}
