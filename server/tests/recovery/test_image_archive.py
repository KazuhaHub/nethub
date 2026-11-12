import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

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

    def test_containerd_gzip_layer_checks_stored_and_uncompressed_bytes(self):
        layer = b'original layer content' * 100
        compressed = gzip.compress(layer, mtime=0)
        for mutation in ('valid', 'blob_digest', 'diff_id', 'expanded_bound', 'truncated'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                stored = compressed[:-3] if mutation == 'truncated' else compressed
                name = 'blobs/sha256/' + hashlib.sha256(stored).hexdigest()
                if mutation == 'blob_digest':
                    name = 'blobs/sha256/' + '0' * 64
                diff = hashlib.sha256(layer).hexdigest() if mutation != 'diff_id' else '0' * 64
                config = json.dumps({'os': 'linux', 'architecture': 'amd64',
                    'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + diff]}}).encode()
                manifest = json.dumps([{'Config': 'config.json', 'RepoTags': ['owned:test'],
                                        'Layers': [name]}]).encode()
                target = Path(directory) / 'images.tar'
                with tarfile.open(target, 'w') as archive:
                    for member, raw in [('manifest.json', manifest), ('config.json', config), (name, stored)]:
                        item = tarfile.TarInfo(member)
                        item.size = len(raw)
                        archive.addfile(item, io.BytesIO(raw))
                with patch('image_archive.MAX_LAYER_BYTES', 10 if mutation == 'expanded_bound' else 1024**3):
                    if mutation == 'valid':
                        self.assertEqual(inspect_archive(target)['owned:test']['layers'], ['sha256:' + diff])
                    else:
                        with self.assertRaises((ValueError, EOFError, OSError)):
                            inspect_archive(target)

    def test_image_ids_bind_containerd_index_to_exact_config_and_layers(self):
        for mutation in ('valid', 'id', 'tag', 'config', 'layer', 'descriptor_bytes'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                blobs = {}

                def blob(raw):
                    digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
                    blobs['blobs/sha256/' + digest[7:]] = raw
                    return {'digest': digest, 'size': len(raw)}

                layer = b'owned runtime layer'
                layer_descriptor = blob(gzip.compress(layer, mtime=0))
                config = blob(json.dumps({'os': 'linux', 'architecture': 'amd64',
                    'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + hashlib.sha256(layer).hexdigest()]}}).encode())
                runtime = {'schemaVersion': 2, 'config': dict(config), 'layers': [dict(layer_descriptor)]}
                if mutation == 'config':
                    runtime['config']['digest'] = 'sha256:' + '0' * 64
                if mutation == 'layer':
                    runtime['layers'][0]['size'] += 1
                manifest_descriptor = blob(json.dumps(runtime).encode())
                manifest_descriptor['platform'] = {'os': 'linux', 'architecture': 'amd64'}
                root = blob(json.dumps({'schemaVersion': 2, 'manifests': [manifest_descriptor]}).encode())
                identifier = root['digest']
                root['annotations'] = {'io.containerd.image.name': 'docker.io/library/owned:test'}
                if mutation == 'tag':
                    root['annotations']['io.containerd.image.name'] = 'unrelated:test'
                if mutation == 'descriptor_bytes':
                    blobs['blobs/sha256/' + identifier[7:]] += b' '
                blobs['index.json'] = json.dumps({'schemaVersion': 2, 'manifests': [root]}).encode()
                blobs['manifest.json'] = json.dumps([{'Config': 'blobs/sha256/' + config['digest'][7:],
                    'RepoTags': ['owned:test'], 'Layers': ['blobs/sha256/' + layer_descriptor['digest'][7:]]}]).encode()
                target = Path(directory) / 'images.tar'
                with tarfile.open(target, 'w') as archive:
                    for name, raw in blobs.items():
                        item = tarfile.TarInfo(name)
                        item.size = len(raw)
                        archive.addfile(item, io.BytesIO(raw))
                ids = {'owned:test': identifier if mutation != 'id' else 'sha256:' + '0' * 64}
                if mutation == 'valid':
                    actual = inspect_archive(target, ids)
                    self.assertEqual(actual['owned:test']['config'], config['digest'])
                    self.assertEqual(inspect_archive(target, {'owned:test': config['digest']}), actual)
                else:
                    with self.assertRaises(ValueError):
                        inspect_archive(target, ids)


if __name__ == '__main__':
    unittest.main()
