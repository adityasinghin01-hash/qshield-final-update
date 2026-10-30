"""Provider settings must reach both AI features without exposing credentials."""
import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch

from ai_advisor import ask_qshield_ai, get_provider_config, load_dotenv_if_present
from ai_provider import AIError, OpenAIProvider, configured_provider


class AIConfigurationTests(unittest.TestCase):
    def environment(self, **extra):
        return patch.dict(os.environ, {'OPENAI_API_KEY':'test-fixture-secret',
            'QSHIELD_AI_MODEL':'fixture-model', **extra}, clear=True)

    def opener(self, value):
        response=Mock()
        response.__enter__=Mock(return_value=response)
        response.__exit__=Mock(return_value=False)
        response.read.return_value=json.dumps(value).encode()
        opener=Mock();opener.open.return_value=response
        return opener

    def test_patch_uses_configured_base_url(self):
        opener=self.opener({'status':'completed','output':[{'type':'message','content':[{'type':'output_text','text':'{"ok":true}'}]}]})
        with self.environment(QSHIELD_AI_BASE_URL='https://gateway.example/v1/'), patch('urllib.request.build_opener',return_value=opener):
            self.assertEqual(OpenAIProvider().generate_json('test',{},{}), {'ok':True})
        self.assertEqual(opener.open.call_args.args[0].full_url,'https://gateway.example/v1/responses')

    def test_agentrouter_alias_and_chat_protocol(self):
        opener=self.opener({'choices':[{'finish_reason':'stop','message':{'content':'{"ok":true}'}}]})
        with self.environment(QSHIELD_AI_PROVIDER='agentrouter',QSHIELD_AI_BASE_URL='https://gateway.example/v1'), patch('urllib.request.build_opener',return_value=opener):
            self.assertEqual(configured_provider().generate_json('test',{},{}), {'ok':True})
        req=opener.open.call_args.args[0]
        self.assertEqual(req.full_url,'https://gateway.example/v1/chat/completions')
        self.assertEqual(json.loads(req.data)['response_format']['type'],'json_schema')
        self.assertNotIn('test-fixture-secret',req.data.decode())

    def test_router_requires_explicit_endpoint(self):
        with self.environment(QSHIELD_AI_PROVIDER='agentrouter'), self.assertRaisesRegex((AIError,ValueError),'base URL|BASE_URL'):
            configured_provider()

    def test_dotenv_export_quotes_and_comments(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ,{},clear=True):
            path=Path(temp)/'.env'
            path.write_text('\ufeffexport OPENAI_API_KEY="test-fixture-secret" # comment\nQSHIELD_AI_MODEL=fixture-model # comment\nQSHIELD_AI_BASE_URL="https://gateway.example/v1"\n')
            load_dotenv_if_present(path)
            cfg=get_provider_config()
            self.assertEqual(cfg['api_key'],'test-fixture-secret')
            self.assertEqual(cfg['model'],'fixture-model')
            self.assertEqual(cfg['base_url'],'https://gateway.example/v1')

    def test_invalid_endpoint_rejected_before_credentials_leave(self):
        for url in ('https://user:pass@gateway.example/v1','http://gateway.example/v1','https://gateway.example/v1?token=private','ftp://gateway.example/v1'):
            with self.subTest(url=url),self.environment(QSHIELD_AI_BASE_URL=url),patch('urllib.request.build_opener') as transport:
                with self.assertRaises((AIError,ValueError)):
                    OpenAIProvider().generate_json('test',{},{})
                transport.assert_not_called()

    def test_chat_auth_error_is_actionable_and_sanitized(self):
        opener=Mock();opener.open.side_effect=urllib.error.HTTPError('https://gateway.example/v1/chat/completions',401,'unauthorized',{},io.BytesIO(b'{"error":{"message":"test-fixture-secret"}}'))
        with self.environment(QSHIELD_AI_BASE_URL='https://gateway.example/v1'),patch('urllib.request.build_opener',return_value=opener):
            with self.assertRaises(RuntimeError) as error:
                ask_qshield_ai('Hello')
        self.assertIn('401',str(error.exception))
        self.assertIn('base URL',str(error.exception))
        self.assertNotIn('test-fixture-secret',str(error.exception))

    def test_chat_and_patch_share_aliases(self):
        with patch.dict(os.environ,{'QSHIELD_AI_API_KEY':'test-fixture-secret','OPENAI_MODEL':'fixture-model','OPENAI_BASE_URL':'https://gateway.example/v1'},clear=True):
            provider=OpenAIProvider()
            self.assertEqual(provider.model,'fixture-model')
            self.assertEqual(provider.base_url,'https://gateway.example/v1')


if __name__=='__main__': unittest.main()
