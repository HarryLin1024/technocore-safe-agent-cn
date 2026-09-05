import io
import json
import tempfile
import unittest
import subprocess
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import agent
import audit
import delivery


class WorkflowTests(unittest.TestCase):
    def test_scanner_finds_secret_retained_only_in_git_history(self):
        with tempfile.TemporaryDirectory() as directory:
            def git(*args):
                return subprocess.run(['git', *args], cwd=directory, check=True, capture_output=True).stdout
            git('init', '-q')
            git('config', 'user.name', 'Audit Test')
            git('config', 'user.email', 'audit@example.com')
            path = Path(directory) / 'fixture.txt'
            path.write_text('ghp_' + 'a' * 32)
            git('add', 'fixture.txt')
            git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'synthetic fixture')
            path.write_text('clean working version')
            git('add', 'fixture.txt')
            git('-c', 'commit.gpgsign=false', 'commit', '-qm', 'clean fixture')
            with mock.patch('audit.git', side_effect=git):
                report = audit.scan()
            self.assertEqual(report['commits'], 2)
            self.assertGreater(report['findings']['credential'], 0)

    def test_archived_public_receipts_verify_without_private_key(self):
        bundle = json.loads((Path(__file__).parent / 'receipts/signed/codex-flop-cn-12-15.json').read_text())
        self.assertEqual(len(bundle['records']), 4)
        for record in bundle['records']:
            self.assertEqual(agent.verify_export_record(bundle['room'], record), 'verified')

    def test_delivery_lock_excludes_concurrent_operations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'identity.json'
            with delivery.journal(path):
                with self.assertRaisesRegex(ValueError, 'another delivery'):
                    with delivery.journal(path):
                        pass

    def test_scanner_detects_synthetic_secrets_and_errors_fail_closed(self):
        fake = b'"private_key_hex": "' + b'a' * 64 + b'"'
        self.assertIn('private_material', audit.findings(fake))
        self.assertIn('credential', audit.findings(b'ghp_' + b'a' * 32))
        self.assertTrue(audit.sensitive_name('.agent-state/delivery.sqlite3'))
        with mock.patch('audit.scan', side_effect=OSError('synthetic')), redirect_stderr(io.StringIO()):
            self.assertEqual(audit.main(), 2)
        with mock.patch('audit.scan', return_value={'findings': {'credential': 1}}), redirect_stdout(io.StringIO()):
            self.assertEqual(audit.main(), 1)
        with mock.patch('audit.scan', return_value={'findings': {}}), redirect_stdout(io.StringIO()):
            self.assertEqual(audit.main(), 0)

    def test_deep_json_is_bounded_but_brackets_in_strings_are_not_nesting(self):
        with self.assertRaisesRegex(ValueError, 'nesting'):
            agent.strict_json_loads('[' * 1500 + '0' + ']' * 1500)
        self.assertEqual(agent.strict_json_loads(json.dumps('[' * 100)), '[' * 100)

    def test_missing_file_cli_does_not_disclose_path(self):
        output = io.StringIO()
        with mock.patch('sys.argv', ['agent.py', '--key-file', '/synthetic/missing', 'status']), redirect_stderr(output):
            self.assertEqual(agent.main(), 1)
        self.assertNotIn('/synthetic', output.getvalue())

    def test_identity_publication_cannot_overwrite_concurrent_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'identity.json'
            original_link = agent.os.link
            def raced_link(src, dst, **kwargs):
                target.write_bytes(b'concurrent identity')
                return original_link(src, dst, **kwargs)
            with mock.patch('agent.os.link', side_effect=raced_link), self.assertRaises(FileExistsError):
                agent.generate_identity(target)
            self.assertEqual(target.read_bytes(), b'concurrent identity')

    def test_unknown_send_blocks_retry_and_absence_does_not_clear_it(self):
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / 'identity.json'
            request = mock.Mock(side_effect=OSError('timeout'))
            args = (key_path, agent.DEFAULT_BASE_URL, 'lobby', 'did', '123', 'text', request, mock.Mock())
            with self.assertRaises(OSError):
                delivery.deliver(*args)
            with self.assertRaisesRegex(ValueError, 'already recorded'):
                delivery.deliver(*args)
            self.assertEqual(request.call_count, 1)
            export = Path(directory) / 'empty.jsonl'
            export.write_bytes(b'')
            with redirect_stdout(io.StringIO()):
                delivery.command_reconcile(SimpleNamespace(key_file=key_path, base_url=agent.DEFAULT_BASE_URL, room='lobby', export_file=export))
            with delivery.journal(key_path) as db:
                self.assertEqual(db.execute('SELECT state FROM deliveries').fetchone()[0], 'unknown')

    def test_reconcile_and_receipt_independently_verify_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'identity.json'
            key, did = agent.generate_identity(path)
            record = {'seq': 1, 'ts': '2026-09-05T00:00:00Z', 'from': did, 'nonce': 123,
                      'text': 'published', 'sig': agent.sign_message(key, 'lobby', '123', 'published')}
            with self.assertRaises(OSError):
                delivery.deliver(path, agent.DEFAULT_BASE_URL, 'lobby', did, '123', 'published',
                                 mock.Mock(side_effect=OSError()), mock.Mock())
            export = Path(directory) / 'export.jsonl'
            export.write_text(json.dumps(record) + '\n')
            args = SimpleNamespace(key_file=path, base_url=agent.DEFAULT_BASE_URL, room='lobby', export_file=export)
            with redirect_stdout(io.StringIO()):
                delivery.command_reconcile(args)
            with delivery.journal(path) as db:
                identifier, state = db.execute('SELECT id,state FROM deliveries').fetchone()
            self.assertEqual(state, 'confirmed')
            output = io.StringIO()
            with redirect_stdout(output):
                delivery.command_receipt(SimpleNamespace(key_file=path, delivery_id=identifier))
            receipt = json.loads(output.getvalue())
            self.assertEqual(agent.verify_export_record(receipt['room'], receipt['record']), 'verified')
