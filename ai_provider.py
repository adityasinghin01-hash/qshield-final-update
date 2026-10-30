"""Backend AI transport: explicit endpoint, bounded output, no redirect or retry."""
from __future__ import annotations
import json
import urllib.error
import urllib.request
from typing import Protocol
from ai_config import get_provider_config


class AIError(RuntimeError):
    """Safe public error, excluding upstream bodies, credentials and headers."""


class AIProvider(Protocol):
    def generate_json(self, instructions: str, context: dict, schema: dict) -> dict: ...


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def safe_http_error(error):
    """Keep only recognized error codes; upstream messages may echo the key."""
    status = error.code
    code = None
    try:
        data = json.loads(error.read(16_001))
        detail = data.get('error') if isinstance(data, dict) else None
        candidate = detail.get('code') if isinstance(detail, dict) else None
        if candidate in ('invalid_api_key', 'insufficient_quota', 'rate_limit_exceeded',
                         'model_not_found', 'permission_denied'):
            code = candidate
    except (ValueError, TypeError, OSError):
        pass
    finally:
        error.close()
    hints = {401:'Check that the key belongs to this base URL and is active.',
             403:'The provider denied access; check account and model permissions.',
             404:'Check the base URL, API protocol and exact model ID.',
             429:'Provider quota or rate limit reached; check balance and limits.'}
    label = ' ('+code+')' if code else ''
    result = AIError('AI provider HTTP '+str(status)+label+'. '+hints.get(status,'Check provider availability and API protocol.'))
    result.http_status = status
    result.error_code = code or 'provider_rejected_request'
    return result


def request_json(config, path, payload):
    request = urllib.request.Request(config['base_url']+'/'+path,
        data=json.dumps(payload).encode(),headers={'Authorization':'Bearer '+config['api_key'], 'Content-Type':'application/json'},method='POST')
    try:
        with urllib.request.build_opener(NoRedirect).open(request,timeout=config['timeout']) as response:
            raw=response.read(128_001)
        if len(raw)>128_000:
            raise AIError('AI response exceeded the size limit.')
        result=json.loads(raw)
        if not isinstance(result,dict):
            raise ValueError
        return result
    except urllib.error.HTTPError as error:
        raise safe_http_error(error) from None
    except AIError:
        raise
    except (TimeoutError,urllib.error.URLError,OSError,ValueError,TypeError):
        raise AIError('AI request failed or returned invalid data. Check backend base URL, connectivity and timeout.') from None


class OpenAIProvider:
    def __init__(self):
        try:
            self.config=get_provider_config()
        except ValueError as error:
            raise AIError(str(error)) from None
        self._key=self.config['api_key']
        self.model=self.config['model']
        self.base_url=self.config['base_url']
        self.timeout=self.config['timeout']
        if not self._key or not self.model:
            raise AIError('Configure OPENAI_API_KEY and QSHIELD_AI_MODEL on the backend.')
        if self.config['provider'] in ('mock','offline'):
            raise AIError('Mock mode supports chat only; Q-Patch needs a configured live provider.')

    def generate_json(self,instructions,context,schema):
        output_format={'type':'json_schema','name':'qshield_proposal','strict':True,'schema':schema}
        if self.config['api']=='chat_completions':
            body={'model':self.model,'messages':[{'role':'system','content':instructions},
                  {'role':'user','content':json.dumps(context)}], 'max_tokens':4000,
                  'response_format':{'type':'json_schema','json_schema':{k:v for k,v in output_format.items() if k!='type'}}}
            result=request_json(self.config,'chat/completions',body)
            try:
                choice=result['choices'][0]
                if choice.get('finish_reason')!='stop' or choice['message'].get('refusal'):
                    raise AIError('AI response was incomplete or refused. No patch was generated.')
                text=choice['message']['content']
            except (TypeError,KeyError,IndexError):
                raise AIError('AI provider returned invalid completion data.') from None
        else:
            body={'model':self.model,'store':False,'instructions':instructions,'input':json.dumps(context),
                  'max_output_tokens':4000,'text':{'format':output_format}}
            result=request_json(self.config,'responses',body)
            if result.get('status')!='completed':
                raise AIError('AI response was incomplete. No patch was generated.')
            try:
                parts=[p for item in result.get('output',[]) if item.get('type')=='message' for p in item.get('content',[])]
                if any(p.get('type')=='refusal' for p in parts):
                    raise AIError('AI provider declined this request. No patch was generated.')
                text=''.join(p.get('text','') for p in parts if p.get('type')=='output_text')
            except (AttributeError,TypeError):
                raise AIError('AI provider returned invalid completion data.') from None
        try:
            if not isinstance(text,str) or self._key in text:
                raise ValueError
            value=json.loads(text)
            if not isinstance(value,dict):
                raise ValueError
            return value
        except (ValueError,TypeError):
            raise AIError('AI response was invalid or contained sensitive material and was rejected.') from None


def configured_provider() -> AIProvider:
    return OpenAIProvider()
