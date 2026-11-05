"""Verify saved image configuration and every uncompressed rootfs layer."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile


def inspect_archive(path):
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
                with archive.extractfile(item) as stream:
                    layers.append('sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest())
            if config['rootfs'] != {'type': 'layers', 'diff_ids': layers}:
                raise ValueError('Saved layer bytes differ from image configuration')
            for tag in manifest['RepoTags']:
                if tag in result or not isinstance(tag, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_./:-]{0,255}', tag):
                    raise ValueError('Saved image tag ambiguous')
                result[tag] = {'config': config_digest, 'layers': layers}
        if not result:
            raise ValueError('Saved image tags missing')
        return result


if __name__ == '__main__':
    try:
        print(json.dumps(inspect_archive(Path(sys.argv[1])), sort_keys=True))
    except Exception:
        raise SystemExit('Saved image content verification failed') from None
