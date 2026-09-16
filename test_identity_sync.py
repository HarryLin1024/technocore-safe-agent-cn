import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import agent


class IdentitySyncTests(unittest.TestCase):
    def test_directory_sync_follows_publication(self):
        events = []
        real_sync, real_link = os.fsync, os.link
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'synthetic.json'

            def sync(fd):
                events.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
                real_sync(fd)

            def link(*args, **kwargs):
                real_link(*args, **kwargs)
                events.append('publish')

            with mock.patch('agent.os.fsync', side_effect=sync), mock.patch('agent.os.link', side_effect=link):
                agent.generate_identity(target)
            self.assertEqual(events, ['file', 'publish', 'directory'])

    def test_failed_directory_sync_preserves_identity_and_refuses_replacement(self):
        real_sync = os.fsync
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'synthetic.json'

            def sync(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    raise OSError('synthetic storage failure')
                real_sync(fd)

            with mock.patch('agent.os.fsync', side_effect=sync):
                with self.assertRaisesRegex(ValueError, 'durability uncertain'):
                    agent.generate_identity(target)
            agent.load_identity(target)
            with self.assertRaises(FileExistsError):
                agent.generate_identity(target)
