"""Connection diagnostics must distinguish config presence from authentication."""
import io
import json
import unittest
import urllib.error
from unittest.mock import Mock, patch

from ai_provider import request_json, AIError

FIXTURE={'api_key':'fixture-secret','base_url':'https://api.example/v1',
         'model':'fixture-model','provider':'openai','timeout':5,'api':'responses'}


class ConnectionDiagnosticsTests(unittest.TestCase):
    def check(self):
        from ai_diagnostics import check_ai_connection
        return check_ai_connection(FIXTURE)

    def response(self,data):
        response=Mock()
        response.__enter__=Mock(return_value=response)
        response.__exit__=Mock(return_value=False)
        response.read.return_value=json.dumps(data).encode()
        opener=Mock();opener.open.return_value=response
        return opener

    def test_present_key_is_not_proof_until_authenticated(self):
        opener=self.response({'data':[{'id':'fixture-model'}]})
        with patch('urllib.request.build_opener',return_value=opener):
            data=self.check()
        self.assertTrue(data['connection_verified'])
        self.assertTrue(data['model_available'])
        request=opener.open.call_args.args[0]
        self.assertEqual(request.get_method(),'GET')
        self.assertEqual(request.full_url,'https://api.example/v1/models')
        self.assertNotIn('fixture-secret',json.dumps(data))

    def test_invalid_key_is_reported_without_provider_body(self):
        error=urllib.error.HTTPError('https://api.example/v1/models',401,'Unauthorized',{},io.BytesIO(b'{"error":{"code":"invalid_api_key","message":"fixture-secret"}}'))
        opener=Mock();opener.open.side_effect=error
        with patch('urllib.request.build_opener',return_value=opener): data=self.check()
        self.assertFalse(data['connection_verified'])
        self.assertEqual(data['http_status'],401)
        self.assertEqual(data['error_code'],'invalid_api_key')
        self.assertNotIn('fixture-secret',json.dumps(data))

    def test_authenticated_but_missing_model(self):
        with patch('urllib.request.build_opener',return_value=self.response({'data':[{'id':'other-model'}]})):
            data=self.check()
        self.assertTrue(data['connection_verified'])
        self.assertFalse(data['model_available'])
        self.assertFalse(data['ready'])

    def test_chat_error_preserves_safe_provider_code(self):
        error=urllib.error.HTTPError('https://api.example/v1/chat/completions',401,'Unauthorized',{},io.BytesIO(b'{"error":{"code":"invalid_api_key","message":"fixture-secret"}}'))
        opener=Mock();opener.open.side_effect=error
        with patch('urllib.request.build_opener',return_value=opener),self.assertRaises(AIError) as caught:
            request_json(FIXTURE,'chat/completions',{})
        self.assertIn('invalid_api_key',str(caught.exception))
        self.assertNotIn('fixture-secret',str(caught.exception))

    def test_network_failure_is_not_authentication_rejection(self):
        opener=Mock();opener.open.side_effect=urllib.error.URLError('fixture-secret')
        with patch('urllib.request.build_opener',return_value=opener):data=self.check()
        self.assertFalse(data['connection_verified'])
        self.assertEqual(data['error_code'],'connection_failed')
        self.assertIsNone(data['http_status'])
        self.assertNotIn('fixture-secret',json.dumps(data))


class DiagnosticsEndpointTests(unittest.TestCase):
    def post(self,payload):
        import dashboard
        handler=object.__new__(dashboard.DashboardRequestHandler)
        body=json.dumps(payload).encode()
        handler.path='/api/ai/check'
        handler.headers={'Content-Length':str(len(body))}
        handler.rfile=io.BytesIO(body)
        sent=[]
        handler.send_json=lambda status,data:sent.append((status,data))
        handler.send_error_json=lambda status,error:sent.append((status,{'error':error}))
        handler.do_POST()
        return sent[0]

    def test_explicit_check_returns_safe_auth_failure(self):
        safe={'connection_verified':False,'http_status':401,'error_code':'invalid_api_key'}
        with patch('dashboard.check_ai_connection',return_value=safe) as check:
            self.assertEqual(self.post({}),(200,safe))
        check.assert_called_once_with()

    def test_browser_cannot_supply_credentials_or_endpoint(self):
        for payload in ({'api_key':'fixture-secret'},{'base_url':'https://other.example/v1'}):
            with self.subTest(payload=payload),patch('dashboard.check_ai_connection') as check:
                self.assertEqual(self.post(payload)[0],400)
                check.assert_not_called()


if __name__=='__main__':unittest.main()
