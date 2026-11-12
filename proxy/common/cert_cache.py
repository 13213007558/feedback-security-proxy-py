# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       pki
       fcntl
"""
import os
import ssl
import time
import base64
import hashlib
import logging
import tempfile
import threading
import contextlib
import subprocess
from typing import Any, Callable, Dict, List, Optional, Tuple

from .constants import IS_WINDOWS


logger = logging.getLogger(__name__)


# A generator receives the host name, the parsed upstream certificate dict
# and the :class:`LeafPaths` it must populate.  It writes the generated
# material to the *temp* paths carried by :class:`LeafPaths` and must not
# touch the final cache paths itself -- atomic publishing is owned by the
# cache.  A raised exception aborts the publication.
CertificateGenerator = Callable[[str, Dict[str, Any], 'LeafPaths'], None]


def sha256_fingerprint(pem_path: str) -> Optional[str]:
    """Return the base64 SHA-256 fingerprint of the DER body of a PEM file."""
    try:
        with open(pem_path, 'rb') as pem:
            der = ssl.PEM_cert_to_DER_cert(pem.read().decode('utf-8'))
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    digest = hashlib.sha256(der).digest()
    return base64.b64encode(digest).decode('ascii')


def _extract_public_key_pem(output: bytes) -> Optional[bytes]:
    """Keep only the PUBLIC KEY block of an openssl stdout.

    LibreSSL appends the full certificate to the output of
    ``openssl x509 -pubkey``, so the stream cannot be hashed verbatim.
    """
    begin = b'-----BEGIN PUBLIC KEY-----'
    end = b'-----END PUBLIC KEY-----'
    start = output.find(begin)
    stop = output.find(end)
    if start == -1 or stop == -1:
        return None
    return output[start:stop + len(end)]


def public_key_fingerprint(
        path: str,
        kind: str,
        timeout: int,
        openssl: str,
) -> Optional[str]:
    """SHA-256 fingerprint of the public key embedded in ``path``.

    ``kind`` is ``x509`` for certificates and ``rsa`` for private keys.
    Different openssl subcommands are required because LibreSSL rejects
    feeding a certificate to ``openssl rsa``.  Returns ``None`` when the
    material cannot be parsed, e.g. a corrupted cache file.
    """
    if kind == 'x509':
        command = [openssl, 'x509', '-in', path, '-pubkey', '-outform', 'PEM']
    else:
        command = [openssl, 'rsa', '-in', path, '-pubout', '-outform', 'PEM']
    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, _ = proc.communicate(timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    public_key = _extract_public_key_pem(stdout)
    if public_key is None:
        return None
    return hashlib.sha256(public_key).hexdigest()


def decode_certificate(pem_path: str) -> Optional[Dict[str, Any]]:
    """Parse a PEM certificate file using the stdlib SSL decoder."""
    # pylint: disable=import-outside-toplevel
    import _ssl  # noqa: WPS436
    try:
        return _ssl._test_decode_cert(pem_path)  # type: ignore[attr-defined]
    except (OSError, ssl.SSLError, ValueError):
        return None


def _as_epoch(value: str) -> Optional[float]:
    for fmt in ('%b %d %H:%M:%S %Y %Z', '%b %d %H:%M:%S %Y'):
        try:
            return time.mktime(time.strptime(value, fmt))
        except ValueError:
            continue
    return None


def _is_certificate_active(certificate: Dict[str, Any]) -> bool:
    not_before = _as_epoch(certificate.get('notBefore', ''))
    not_after = _as_epoch(certificate.get('notAfter', ''))
    if not_before is None or not_after is None:
        return False
    now = time.time()
    return not_before <= now <= not_after


def _matches_host(certificate: Dict[str, Any], host: str) -> bool:
    """Whether the certificate was generated for ``host``.

    The subject common name and every SAN DNS entry must describe the
    requested host; a certificate minted for another host is never reused
    merely because it happens to share the cache file name.
    """
    candidates: List[str] = []
    for rdn in certificate.get('subject', ()):
        for key, value in rdn:
            if key == 'commonName':
                candidates.append(value)
    for san in certificate.get('subjectAltName', ()):
        if san[0] == 'DNS':
            candidates.append(san[1])
    if not candidates:
        return False
    return host in candidates


@contextlib.contextmanager
def _file_lock(lock_path: str) -> Any:
    """Best-effort cross-process exclusive lock.

    On POSIX systems an flock guarded lock file serializes concurrent
    workers (including separate proxy processes sharing a cache directory).
    On platforms without :mod:`fcntl` the lock degrades to a no-op while
    in-process threading locks still provide the deterministic guarantee.
    """
    if IS_WINDOWS:
        yield None
        return
    import fcntl  # noqa: WPS433
    with open(lock_path, 'a+') as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield lock_file
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


class LeafPaths:
    """On-disk paths of a cached leaf certificate and its side material."""

    def __init__(self, cache_dir: str, host: str) -> None:
        self.host = host
        self.pem = os.path.join(cache_dir, '%s.pem' % host)
        self.pub = os.path.join(cache_dir, '%s.pub' % host)
        self.csr = os.path.join(cache_dir, '%s.csr' % host)
        self.meta = os.path.join(cache_dir, '%s.meta' % host)
        self.lock = os.path.join(cache_dir, '%s.lock' % host)

    def temp_paths(self, work_dir: str) -> 'LeafPaths':
        token = '%s-%d-%d' % (self.host, os.getpid(), threading.get_ident())
        scratch = LeafPaths(work_dir, token)
        scratch.host = self.host
        return scratch


class CertificateGenerationError(RuntimeError):
    """Raised when leaf material could not be generated or published."""


class CertificateCache:
    """Identity-aware, validated cache of dynamically signed host certs.

    A cache entry is only reused when all of the following hold:

    1. The PEM parses, is within its validity window and was issued for the
       requested host identity (CN/SAN), rather than merely sharing a file
       name.
    2. The issuing CA certificate still verifies the cached leaf, so certs
       signed by a previous interception CA are regenerated.
    3. The public key of the leaf matches the configured signing key, so a
       replaced signing key forces regeneration.
    4. The sidecar metadata fingerprints match the current CA and signing
       configuration, which makes the decision deterministic without
       re-running openssl on every connection.

    Publication is atomic (temp files + ``os.replace``) and generation is
    serialized per host both across threads (in-process lock registry) and
    across processes (flock).  Failed generation never leaves a file that a
    later request could mistake for a valid cached certificate.
    """

    SIDECAR_VERSION = 1

    def __init__(
            self,
            cache_dir: str,
            ca_cert_file: str,
            ca_key_file: str,
            signing_key_file: str,
            generator: CertificateGenerator,
            openssl: str = 'openssl',
            timeout: int = 10,
    ) -> None:
        self.cache_dir = cache_dir
        self.ca_cert_file = ca_cert_file
        self.ca_key_file = ca_key_file
        self.signing_key_file = signing_key_file
        self.generator = generator
        self.openssl = openssl
        self.timeout = timeout
        os.makedirs(self.cache_dir, exist_ok=True)
        self._thread_locks: Dict[str, threading.Lock] = {}
        self._lock_registry_guard = threading.Lock()
        self._memo: Dict[str, Tuple[int, int, str]] = {}
        self._audit_report: Optional[Dict[str, List[Dict[str, str]]]] = None
        self.configuration_warnings: List[str] = self._check_configuration()
        for warning in self.configuration_warnings:
            logger.warning('TLS interception configuration issue: %s', warning)

    def get(
            self,
            host: str,
            certificate: Dict[str, Any],
    ) -> str:
        """Return a validated leaf cert path for ``host``.

        Reuses the cached certificate when it still matches the host
        identity, issuing CA and configured signing key; otherwise a fresh
        certificate is generated and atomically published.
        """
        paths = LeafPaths(self.cache_dir, host)
        if self._memo_hit(paths.pem):
            return paths.pem
        thread_lock = self._thread_lock(host)
        with thread_lock, _file_lock(paths.lock):
            # Re-check after acquiring the locks: another thread or process
            # may have published a valid entry while we were waiting.
            valid, _ = self._validate(paths, host)
            if valid:
                self._remember(paths.pem)
                return paths.pem
            self._regenerate(host, certificate, paths)
            valid, reason = self._validate(paths, host)
            if not valid:
                raise CertificateGenerationError(
                    'Generated certificate for host %s failed validation: %s'
                    % (host, reason),
                )
            self._remember(paths.pem)
            return paths.pem

    def audit(self) -> Dict[str, List[Dict[str, str]]]:
        """Scan the cache directory and classify every cached leaf cert.

        Returns a dict with ``valid``, ``stale`` and ``corrupt`` lists.
        Each entry carries the host, certificate path and a human readable
        reason.  This is the operations-facing view of which old cache
        files are still trusted and which will be regenerated on demand.
        """
        report: Dict[str, List[Dict[str, str]]] = {
            'valid': [],
            'stale': [],
            'corrupt': [],
        }
        for name in sorted(os.listdir(self.cache_dir)):
            if not name.endswith('.pem'):
                continue
            host = name[:-4]
            paths = LeafPaths(self.cache_dir, host)
            valid, reason = self._validate(paths, host)
            bucket = 'valid' if valid else (
                'corrupt' if reason.startswith('corrupt') else 'stale'
            )
            report[bucket].append({
                'host': host,
                'path': paths.pem,
                'reason': reason,
            })
        return report

    def log_audit(self) -> Dict[str, List[Dict[str, str]]]:
        """Run :meth:`audit` once per process and emit an ops log summary.

        Subsequent calls return the cached report so the per-connection
        hot path never rescans the cache directory.
        """
        if self._audit_report is not None:
            return self._audit_report
        report = self.audit()
        self._audit_report = report
        logger.warning(
            'Certificate cache audit (%s): %d valid, %d stale, %d corrupt',
            self.cache_dir,
            len(report['valid']),
            len(report['stale']),
            len(report['corrupt']),
        )
        for entry in report['stale']:
            logger.warning(
                'Stale cached certificate %s (%s); will be re-signed on use',
                entry['path'], entry['reason'],
            )
        for entry in report['corrupt']:
            logger.warning(
                'Corrupt cached certificate %s (%s); will be regenerated on use',
                entry['path'], entry['reason'],
            )
        return report

    def _check_configuration(self) -> List[str]:
        """Detect inconsistent CA / signing material at construction time."""
        warnings: List[str] = []
        expected: List[Tuple[str, str, str]] = [
            (self.ca_cert_file, 'x509', 'CA certificate (--ca-cert-file)'),
            (self.ca_key_file, 'rsa', 'CA private key (--ca-key-file)'),
            (self.signing_key_file, 'rsa',
             'signing private key (--ca-signing-key-file)'),
        ]
        fingerprints: Dict[str, Optional[str]] = {}
        for path, kind, label in expected:
            if not os.path.isfile(path):
                warnings.append('%s is missing: %s' % (label, path))
                fingerprints[label] = None
                continue
            fingerprint = public_key_fingerprint(
                path, kind, self.timeout, self.openssl,
            )
            if fingerprint is None:
                warnings.append('%s is unreadable or invalid: %s' % (label, path))
            fingerprints[label] = fingerprint
        ca_cert = fingerprints.get('CA certificate (--ca-cert-file)')
        ca_key = fingerprints.get('CA private key (--ca-key-file)')
        if ca_cert is not None and ca_key is not None and ca_cert != ca_key:
            warnings.append(
                'CA certificate %s and CA key %s are not a matching pair'
                % (self.ca_cert_file, self.ca_key_file),
            )
        return warnings

    def _thread_lock(self, host: str) -> threading.Lock:
        with self._lock_registry_guard:
            if host not in self._thread_locks:
                self._thread_locks[host] = threading.Lock()
            return self._thread_locks[host]

    def _memo_hit(self, pem_path: str) -> bool:
        """Fast path used once an entry has been validated in this process."""
        try:
            stat = os.stat(pem_path)
        except OSError:
            self._memo.pop(pem_path, None)
            return False
        cached = self._memo.get(pem_path)
        if cached is None:
            return False
        return cached == (stat.st_dev, stat.st_ino, str(stat.st_mtime_ns))

    def _remember(self, pem_path: str) -> None:
        stat = os.stat(pem_path)
        self._memo[pem_path] = (
            stat.st_dev, stat.st_ino, str(stat.st_mtime_ns),
        )

    def _validate(
            self,
            paths: LeafPaths,
            host: str,
    ) -> Tuple[bool, str]:
        """Full validation of a cached entry against current configuration."""
        if not os.path.isfile(paths.pem):
            return False, 'missing cached certificate'
        certificate = decode_certificate(paths.pem)
        if certificate is None:
            return False, 'corrupt or unparseable certificate file'
        if not _matches_host(certificate, host):
            return False, (
                'certificate identity does not match host %s' % host
            )
        if not _is_certificate_active(certificate):
            return False, 'certificate is expired or not yet valid'
        # Cheap, deterministic fingerprint gate before spawning openssl:
        # anything signed by a previous CA / signing key is rejected here.
        if not self._sidecar_matches(paths):
            return False, (
                'signed by a previous CA or signing key configuration'
            )
        if not self._openssl_verifies(paths.pem):
            return False, 'certificate is not signed by the current CA'
        if not self._public_key_matches(paths.pem):
            return False, (
                'certificate public key does not match the configured '
                'signing key'
            )
        return True, 'ok'

    def _sidecar_matches(self, paths: LeafPaths) -> bool:
        expected = self._expected_meta()
        try:
            with open(paths.meta, 'r', encoding='utf-8') as meta_file:
                lines = [
                    line.strip() for line in meta_file.readlines()
                    if line.strip()
                ]
        except OSError:
            return False
        if len(lines) < 3 or lines[0] != str(self.SIDECAR_VERSION):
            return False
        return lines[1] == expected[0] and lines[2] == expected[1]

    def _expected_meta(self) -> Tuple[str, str]:
        ca_fingerprint = sha256_fingerprint(self.ca_cert_file) or ''
        signing_fingerprint = public_key_fingerprint(
            self.signing_key_file, 'rsa', self.timeout, self.openssl,
        ) or ''
        return ca_fingerprint, signing_fingerprint

    def _openssl_verifies(self, pem_path: str) -> bool:
        command = [
            self.openssl, 'verify',
            '-CAfile', self.ca_cert_file,
            pem_path,
        ]
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            proc.communicate(timeout=self.timeout)
        except (OSError, subprocess.TimeoutExpired):
            return False
        return proc.returncode == 0

    def _public_key_matches(self, pem_path: str) -> bool:
        leaf_fingerprint = public_key_fingerprint(
            pem_path, 'x509', self.timeout, self.openssl,
        )
        signing_fingerprint = public_key_fingerprint(
            self.signing_key_file, 'rsa', self.timeout, self.openssl,
        )
        if leaf_fingerprint is None or signing_fingerprint is None:
            return False
        return leaf_fingerprint == signing_fingerprint

    def _regenerate(
            self,
            host: str,
            certificate: Dict[str, Any],
            paths: LeafPaths,
    ) -> None:
        """Generate into temp files and publish atomically.

        The previous certificate, if any, stays on disk until the freshly
        generated one has been fully validated and replaced; connections
        already using the old file are unaffected because ``os.replace``
        only swaps the directory entry.
        """
        work_dir = tempfile.mkdtemp(
            prefix='proxy-cert-', dir=self.cache_dir,
        )
        scratch = paths.temp_paths(work_dir)
        try:
            try:
                self.generator(host, certificate, scratch)
                for label, temp_path in (
                        ('certificate', scratch.pem),
                        ('public key', scratch.pub),
                        ('CSR', scratch.csr),
                ):
                    if not os.path.isfile(temp_path):
                        raise CertificateGenerationError(
                            'generator did not produce the %s for host %s'
                            % (label, host),
                        )
                # Side material is replaced first.  The certificate PEM is
                # published last so a failure never leaves a new loadable
                # leaf without its matching public key / CSR / sidecar.
                self._atomic_replace(scratch.pub, paths.pub)
                self._atomic_replace(scratch.csr, paths.csr)
                self._atomic_replace(scratch.pem, paths.pem)
                self._write_sidecar(paths)
            except CertificateGenerationError:
                raise
            except Exception as exc:
                raise CertificateGenerationError(
                    'Failed to generate certificate for host %s: %s'
                    % (host, exc),
                ) from exc
        finally:
            self._cleanup_dir(work_dir)

    def _write_sidecar(self, paths: LeafPaths) -> None:
        ca_fingerprint, signing_fingerprint = self._expected_meta()
        payload = '%d\n%s\n%s\n' % (
            self.SIDECAR_VERSION, ca_fingerprint, signing_fingerprint,
        )
        fd, tmp_path = tempfile.mkstemp(
            prefix='.meta-', dir=self.cache_dir,
        )
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as meta_file:
                meta_file.write(payload)
            os.replace(tmp_path, paths.meta)
        except BaseException:
            with contextlib.suppress(OSError):
                os.remove(tmp_path)
            raise

    @staticmethod
    def _atomic_replace(source: str, destination: str) -> None:
        os.replace(source, destination)

    @staticmethod
    def _cleanup_dir(work_dir: str) -> None:
        with contextlib.suppress(OSError):
            for name in os.listdir(work_dir):
                with contextlib.suppress(OSError):
                    os.remove(os.path.join(work_dir, name))
            os.rmdir(work_dir)
