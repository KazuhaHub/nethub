import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from image_archive import inspect_archive


class SavedImageIntegrity(unittest.TestCase):
    def archive(self, directory, *, changed_layer=False, duplicate=False, changed_config=False):
        path = Path(directory) / 'images.tar'
        layer = b'original uncompressed layer fixture'
        config = json.dumps({'os': 'linux', 'architecture': 'amd64',
            'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(layer).hexdigest()]}}).encode()
        manifest = json.dumps([{'Config': 'config.json', 'RepoTags': ['owned:test'], 'Layers': ['layer.tar']}]).encode()
        with tarfile.open(path, 'w') as archive:
            for name, data in [('manifest.json', manifest), ('config.json', config if not changed_config else b'{}'),
                               ('layer.tar', layer if not changed_layer else b'replaced')]:
                item = tarfile.TarInfo(name)
                item.size = len(data)
                archive.addfile(item, io.BytesIO(data))
            if duplicate:
                item = tarfile.TarInfo('layer.tar')
                archive.addfile(item, io.BytesIO())
        return path

    def test_content_identity_and_changed_bytes_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            result = inspect_archive(self.archive(directory))
            self.assertEqual(set(result), {'owned:test'})
            self.assertEqual(len(result['owned:test']['layers']), 1)
        for mutation in ('changed_layer', 'duplicate', 'changed_config'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises((ValueError, KeyError)):
                    inspect_archive(self.archive(directory, **{mutation: True}))


if __name__ == '__main__':
    unittest.main()
