"""Verify saved image configuration and rootfs layers across Docker stores."""
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile


MAX_LAYER_BYTES = 1024**3


def layer_digest(archive, item):
    with archive.extractfile(item) as source:
        compressed = source.read(2) == b'\x1f\x8b'
        source.seek(0)
        stored = hashlib.file_digest(source, 'sha256').hexdigest()
        if item.name.startswith('blobs/sha256/') and item.name != 'blobs/sha256/' + stored:
            raise ValueError('Saved layer blob digest differs')
        source.seek(0)
        stream = gzip.GzipFile(fileobj=source) if compressed else source
        try:
            digest = hashlib.sha256()
            total = 0
            while block := stream.read(1024 * 1024):
                total += len(block)
                if total > MAX_LAYER_BYTES:
                    raise ValueError('Expanded saved layer exceeds its bound')
                digest.update(block)
            return 'sha256:' + digest.hexdigest()
        finally:
            if compressed:
                stream.close()


def inspect_archive(path, identifiers=None):
    if path.stat().st_size > 2 * 1024**3:
        raise ValueError('Image archive exceeds its bound')
    with tarfile.open(path, 'r:') as archive:
        members = {}
        for item in archive.getmembers():
            name = PurePosixPath(item.name)
            if (item.name in members or name.is_absolute() or '..' in name.parts
                    or name.as_posix() != item.name.rstrip('/')
                    or not (item.isfile() or item.isdir()) or item.size > 1024**3):
                raise ValueError('Saved image member refused')
            members[item.name] = item

        def read(name, maximum):
            item = members[name]
            if not item.isfile() or item.size > maximum:
                raise ValueError('Saved image metadata refused')
            with archive.extractfile(item) as stream:
                data = stream.read(maximum + 1)
            if len(data) != item.size:
                raise ValueError('Saved image metadata truncated')
            return data

        manifests = json.loads(read('manifest.json', 1024**2))
        result = {}
        saved = {}
        for manifest in manifests:
            raw = read(manifest['Config'], 1024**2)
            config_digest = 'sha256:' + hashlib.sha256(raw).hexdigest()
            config = json.loads(raw)
            if config.get('os') != 'linux' or config.get('architecture') != 'amd64':
                raise ValueError('Saved image platform differs')
            layers = []
            for name in manifest['Layers']:
                item = members[name]
                if not item.isfile():
                    raise ValueError('Saved layer is not a regular file')
                layers.append(layer_digest(archive, item))
            if config['rootfs'] != {'type': 'layers', 'diff_ids': layers}:
                raise ValueError('Saved layer bytes differ from image configuration')
            for tag in manifest['RepoTags']:
                if tag in result or not isinstance(tag, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_./:-]{0,255}', tag):
                    raise ValueError('Saved image tag ambiguous')
                result[tag] = {'config': config_digest, 'layers': layers}
                saved[tag] = manifest
        if not result:
            raise ValueError('Saved image tags missing')
        if identifiers is not None:
            if set(identifiers) != set(result):
                raise ValueError('Saved image identity tags differ')
            index = json.loads(read('index.json', 1024**2)) if 'index.json' in members else None

            def descriptor_json(descriptor):
                digest = descriptor['digest']
                if not re.fullmatch('sha256:[a-f0-9]{64}', digest):
                    raise ValueError('Saved descriptor digest invalid')
                raw = read('blobs/sha256/' + digest[7:], 1024**2)
                if len(raw) != descriptor['size'] or 'sha256:' + hashlib.sha256(raw).hexdigest() != digest:
                    raise ValueError('Saved descriptor bytes differ')
                return json.loads(raw)

            def runtime_manifest(descriptor, depth=0):
                if depth > 4:
                    raise ValueError('Saved image index nesting exceeds bound')
                value = descriptor_json(descriptor)
                if value.get('schemaVersion') != 2:
                    raise ValueError('Saved image descriptor schema differs')
                if 'manifests' not in value:
                    return value
                candidates = [item for item in value['manifests']
                              if item.get('platform', {}).get('os') == 'linux'
                              and item.get('platform', {}).get('architecture') == 'amd64']
                if len(candidates) != 1:
                    raise ValueError('One saved Linux amd64 manifest required')
                return runtime_manifest(candidates[0], depth + 1)

            for tag, identifier in identifiers.items():
                if identifier == result[tag]['config']:
                    continue
                if not index or index.get('schemaVersion') != 2:
                    raise ValueError('Saved image ID lacks a matching index')
                matches = [item for item in index['manifests']
                           if item.get('digest') == identifier
                           and item.get('annotations', {}).get('io.containerd.image.name')
                           in (tag, 'docker.io/library/' + tag)]
                if len(matches) != 1:
                    raise ValueError('Saved image ID or tag differs from index')
                actual = runtime_manifest(matches[0])
                if (actual['config']['digest'] != result[tag]['config']
                        or actual['config']['size'] != members[saved[tag]['Config']].size
                        or any(not re.fullmatch('sha256:[a-f0-9]{64}', item['digest']) for item in actual['layers'])
                        or ['blobs/sha256/' + item['digest'][7:] for item in actual['layers']]
                        != saved[tag]['Layers']
                        or any(item['size'] != members[name].size
                               for item, name in zip(actual['layers'], saved[tag]['Layers']))):
                    raise ValueError('Saved index references different image content')
        return result


if __name__ == '__main__':
    try:
        print(json.dumps(inspect_archive(Path(sys.argv[1])), sort_keys=True))
    except Exception:
        raise SystemExit('Saved image content verification failed') from None
