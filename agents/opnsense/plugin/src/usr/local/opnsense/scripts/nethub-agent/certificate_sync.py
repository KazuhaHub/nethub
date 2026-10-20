"""Synchronize a current public certificate without changing native GUI settings."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile

from certificate_chain import CertificateChainError, ChainVerifier
from certificate_key import CertificateKeyError, KeyStore
from certificate_protocol import delivery, request_issued, request_settings, submit_request
from certificate_request import CertificateRequestError, RequestStore
from protocol import ProtocolError


class CertificateSyncError(Exception):
    """A fixed diagnostic independent of remote/child error content."""


class CertificateSynchronizer:
    """The caller holds reconcile.lock and checks enabled/revoked/stopped intent.

    Existing keys are mandatory. Accepted missing CSRs are restored from their
    authenticated original bytes; staged generations never move backwards.
    """

    def __init__(self, key_store, verifier=None):
        self.key_store = key_store
        self.verifier = verifier if verifier is not None else ChainVerifier(key_store)
        self.requests = RequestStore(key_store.directory.parent / 'gui-request', key_store)
        self.path = key_store.directory.parent / 'gui-certificate.json'

    def _stage(self, current):
        self.key_store._protected(self.path.parent, directory=True)
        if self.path.exists() or self.path.is_symlink():
            info = self.key_store._protected(self.path)
            if not 1 <= info.st_size <= 65536:
                raise ValueError('Invalid staged generation size')
            raw = self.path.read_bytes()
            previous = json.loads(raw)
            if KeyStore._encoded(previous) != raw:
                raise ValueError('Ambiguous staged generation')
            # An expired staged leaf must not block renewal. Parse its original
            # interval only for immutable identity/monotonicity, not current trust.
            stamp = datetime.strptime(previous['issued']['not_before'], '%Y-%m-%dT%H:%M:%S.%fZ').replace(tzinfo=timezone.utc)
            previous = delivery(previous, current['device_id'], current['assigned_host'].split('.')[0],
                                current['gui_key_fingerprint'], current['request'], now=stamp)
            before, after = previous['issued'], current['issued']
            if before is None or before['generation'] > after['generation']:
                raise ValueError('Staged generation would regress')
            if before['generation'] == after['generation'] and before != after:
                raise ValueError('Issued generation identity changed')
            if before['generation'] != after['generation'] and before['generation_id'] == after['generation_id']:
                raise ValueError('Issued generation identity was reused')
            if raw == KeyStore._encoded(current):
                return
        descriptor, name = tempfile.mkstemp(prefix='.gui-certificate-', dir=self.path.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, 'wb') as stream:
                os.chmod(temporary, 0o600)
                stream.write(KeyStore._encoded(current))
                stream.flush()
                os.fsync(stream.fileno())
            self.key_store._protected(temporary)
            os.replace(temporary, self.path)
            self.key_store._sync(self.path.parent)
        finally:
            temporary.unlink(missing_ok=True)

    def forget(self):
        """Remove only public runtime artifacts after native enrollment clearing.

        This runs before key deletion, under the common mutation lock. It never
        accesses the independent native certificate store or GUI certref.
        """
        self.key_store._protected(self.path.parent, directory=True)
        directory = self.requests.directory
        if directory.exists() or directory.is_symlink():
            self.key_store._protected(directory, directory=True)
            if {path.name for path in directory.iterdir()} - {'request.json'}:
                raise CertificateKeyError('Certificate request cleanup needs local review')
            request = directory / 'request.json'
            if request.exists() or request.is_symlink():
                self.key_store._protected(request)
                request.unlink()
                self.key_store._sync(directory)
            directory.rmdir()
        if self.path.exists() or self.path.is_symlink():
            self.key_store._protected(self.path)
            self.path.unlink()
        self.key_store._sync(self.path.parent)

    def sync(self, origin, secret, device_id, subdomain, context=None):
        try:
            key = self.key_store._load()
            settings = request_settings(origin, secret, device_id, subdomain, key['fingerprint'], context=context)
            host, original = settings['assigned_host'], settings['request']
            if original is None:
                self.requests.ensure(host, key['fingerprint'])
            else:
                self.requests.restore(host, key['fingerprint'], original['csr_der'], original['csr_fingerprint'])
            cached = json.loads((self.requests.directory / 'request.json').read_text())
            admitted = submit_request(origin, secret, device_id, subdomain, key['fingerprint'], cached['csr'], context=context)
            if original is not None and admitted['request'] != original:
                raise ValueError('Accepted original request changed')
            value = request_issued(origin, secret, device_id, subdomain, key['fingerprint'], admitted['request'], context=context)
            value = self.verifier.verify(value, device_id, subdomain, admitted['request'])
            if value['issued'] is None:
                return {'success': True, 'action': 'certificate', 'phase': 'pending', 'message': 'GUI certificate issuance is pending'}
            self._stage(value)
            issued = value['issued']
            return {'success': True, 'action': 'certificate', 'phase': 'verified', 'message': 'GUI certificate verified and staged; native installation is pending',
                    'generation': issued['generation'], 'valid_until': issued['valid_until']}
        except (CertificateChainError, CertificateKeyError, CertificateRequestError, ProtocolError,
                OSError, ValueError, TypeError, KeyError, AttributeError):
            raise CertificateSyncError('GUI certificate synchronization failed; tunnel and native GUI settings were retained') from None
