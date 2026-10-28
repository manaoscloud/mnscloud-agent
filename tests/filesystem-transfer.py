#!/usr/bin/env python3
"""Bounded audio reads never follow links or forward credentials to another origin."""
import importlib.util
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('transfer', ROOT / 'filesystem-transfer.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Connection:
    last = None

    def __init__(self, host, port, **kwargs):
        self.host, self.port, self.kwargs = host, port, kwargs
        self.headers, self.parts = {}, []
        self.closed = False
        Connection.last = self

    def putrequest(self, method, path):
        self.method, self.path = method, path

    def putheader(self, key, value):
        self.headers[key] = value

    def endheaders(self):
        pass

    def send(self, data):
        assert len(data) <= 65536
        self.parts.append(data)

    def getresponse(self):
        return type('Response', (), {'status': 204})()

    def close(self):
        self.closed = True


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.original = module.ROOTS
        module.ROOTS = {**module.ROOTS, 'freeswitch': self.root}
        self.audio = bytes(range(256)) * 2048 + b'\r\n'
        (self.root / 'audio.wav').write_bytes(self.audio)
        self.request = {
            'api': 'https://api.example.invalid/api/v1',
            'agentUUID': '11111111-1111-4111-8111-111111111111',
            'transferUUID': '22222222-2222-4222-8222-222222222222',
            'leaseUUID': '33333333-3333-4333-8333-333333333333',
            'agentToken': 'test-only-placeholder', 'action': 'read',
            'source': 'freeswitch', 'relativePath': 'audio.wav',
            'expiresAt': time.time() + 120,
        }

    def tearDown(self):
        module.ROOTS = self.original
        self.temp.cleanup()

    def test_full_read_preserves_bytes_and_file(self):
        result = module.transfer(self.request, Connection)
        conn = Connection.last
        self.assertEqual(result['bytes'], len(self.audio))
        self.assertEqual(b''.join(conn.parts), self.audio)
        self.assertEqual(conn.host, 'api.example.invalid')
        self.assertEqual(conn.path, '/api/v1/filesystem/transfers/' + self.request['transferUUID'] + '/source')
        self.assertTrue(conn.closed)
        self.assertTrue((self.root / 'audio.wav').exists())

    def test_single_ranges(self):
        for header, expected in [('bytes=1-4', self.audio[1:5]), ('bytes=-2', b'\r\n'),
                                 ('bytes=524288-', b'\r\n')]:
            module.transfer({**self.request, 'range': header}, Connection)
            self.assertEqual(b''.join(Connection.last.parts), expected)
            self.assertEqual(Connection.last.headers['X-MNSCloud-File-Status'], '206')
        for header in ['bytes=0-1,3-4', 'bytes=-0', 'bytes=999999-', 'bytes=4-1', 'items=0-1']:
            with self.assertRaises(ValueError):
                module.byte_range(header, len(self.audio))

    def test_path_and_origin_rejections(self):
        for path in ['../audio.wav', '/audio.wav', 'a/../audio.wav', 'audio.wav\n', 'x\\audio.wav']:
            with self.assertRaises(ValueError):
                module.target('freeswitch', path)
        for api in ['http://api.example.invalid', 'https://user@api.example.invalid',
                    'https://api.example.invalid?target=elsewhere']:
            with self.assertRaises(ValueError):
                module.transfer({**self.request, 'api': api}, Connection)
        with self.assertRaises(ValueError):
            module.transfer({**self.request, 'expiresAt': time.time() - 1}, Connection)
        with self.assertRaises(ValueError):
            module.transfer({**self.request, 'action': 'shell'}, Connection)

    def test_links_fifo_and_directory_rejected(self):
        (self.root / 'link.wav').symlink_to(self.root / 'audio.wav')
        os.link(self.root / 'audio.wav', self.root / 'hard.wav')
        os.mkfifo(self.root / 'pipe.wav')
        (self.root / 'folder.wav').mkdir()
        (self.root / 'linked').symlink_to(self.root, target_is_directory=True)
        for name in ['link.wav', 'hard.wav', 'pipe.wav', 'folder.wav', 'linked/audio.wav']:
            with self.assertRaises((OSError, ValueError)):
                module.transfer({**self.request, 'relativePath': name}, Connection)

    def test_receiver_failure_closes_connection(self):
        class Refusal(Connection):
            def getresponse(self):
                return type('Response', (), {'status': 409})()
        with self.assertRaises(ValueError):
            module.transfer(self.request, Refusal)
        self.assertTrue(Connection.last.closed)
        self.assertEqual((self.root / 'audio.wav').read_bytes(), self.audio)

    def test_exact_media_lifecycle(self):
        module.ROOTS['files'] = self.root
        relative = ('tenants/11111111-1111-4111-8111-111111111111/'
                    'voip-pabx/media-files/audio/2026/01/fixture-v1.wav')
        path = self.root / relative
        path.parent.mkdir(parents=True)
        path.write_bytes(self.audio)
        request = {**self.request, 'source': 'files', 'relativePath': relative,
                   'action': 'inspect', 'expectedSha256': hashlib.sha256(self.audio).hexdigest()}
        inspected = module.transfer(request, Connection)
        self.assertTrue(inspected['exists'])
        self.assertTrue(path.exists())
        with self.assertRaises(ValueError):
            module.transfer({**request, 'action': 'delete', 'expectedSha256': '0' * 64}, Connection)
        self.assertTrue(path.exists())
        self.assertFalse(module.transfer({**request, 'action': 'delete'}, Connection)['exists'])
        self.assertFalse(path.exists())
        self.assertFalse(module.transfer(request, Connection)['exists'])
        with self.assertRaises(ValueError):
            module.transfer({**request, 'source': 'freeswitch'}, Connection)


if __name__ == '__main__':
    unittest.main()
