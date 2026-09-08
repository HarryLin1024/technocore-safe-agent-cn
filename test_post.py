import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import agent


class PostTests(unittest.TestCase):
    def test_full_size_multibyte_send_uses_short_post_route_and_exact_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'identity.json'
            key, did = agent.generate_identity(path)
            text = '中' * 4096
            nonce = '9007199254740993'
            signature = agent.sign_message(key, 'lobby', nonce, text)
            old_url = agent.build_signed_message_url(agent.DEFAULT_BASE_URL, did, 'lobby', nonce, text, signature)
            self.assertGreater(len(old_url.encode()), 32768)
            args = SimpleNamespace(key_file=path, base_url=agent.DEFAULT_BASE_URL,
                                   room='lobby', message=text, timeout=15, commit=True,
                                   show_url=False, ref=None)
            def request(url, timeout, payload):
                self.assertEqual(url, 'https://technocore.chat/r/lobby?format=json')
                self.assertEqual(payload, {'did': did, 'sig': signature, 'nonce': nonce, 'text': text})
                agent.verify_record_signature(key.public_key(), 'lobby', payload['nonce'], payload['text'], payload['sig'])
                return 200, json.dumps({'posted': {'from': did, 'sig': signature,
                    'nonce': int(nonce), 'text': text, 'seq': 1, 'ts': '2026-09-08T00:00:00Z'}})
            with mock.patch('agent.next_nonce', return_value=nonce), mock.patch('agent.request_text', side_effect=request), redirect_stdout(io.StringIO()):
                agent.command_send(args)

    def test_transport_encodes_utf8_json_post_and_keeps_reads_get(self):
        class Response(io.BytesIO):
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.close()
        opener = mock.Mock()
        opener.open.side_effect = lambda *a, **kw: Response(b'{}')
        with mock.patch('agent.urllib.request.build_opener', return_value=opener):
            payload = {'text': '中文', 'nonce': '9007199254740993'}
            agent.request_text('https://localhost/r/lobby', payload=payload)
            req = opener.open.call_args.args[0]
            self.assertEqual(req.get_method(), 'POST')
            self.assertEqual(req.get_header('Content-type'), 'application/json')
            self.assertEqual(json.loads(req.data), payload)
            self.assertIn('中文'.encode(), req.data)
            agent.request_text('https://localhost/config')
            self.assertEqual(opener.open.call_args.args[0].get_method(), 'GET')

    def test_oversized_post_is_rejected_before_network(self):
        opener = mock.Mock()
        with mock.patch('agent.urllib.request.build_opener', return_value=opener):
            with self.assertRaisesRegex(ValueError, '256 KiB'):
                agent.request_text('https://localhost', payload={'text': 'x' * (256 * 1024)})
            opener.open.assert_not_called()
