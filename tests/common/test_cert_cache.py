# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    These tests build two real local CAs with openssl and exercise the
    identity-aware certificate cache against a temporary cache directory.
"""
import os
import time
import types
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from proxy.common import pki
from proxy.common.cert_cache import (
    LeafPaths, CertificateCache, CertificateGenerationError,
    public_key_fingerprint, sha256_fingerprint,
)


class CertCacheTestBase(unittest.TestCase):

    def setUp(self) -> None:
        self.base_dir = tempfile.mkdtemp(prefix='proxy-cert-cache-test-')
        self.ca_one = self._build_ca('ca-one')
        self.ca_two = self._build_ca('ca-two')
        self.upstream_cert = {
            'subject': ((('commonName', 'upstream.example'),),),
        }

    def tearDown(self) -> None:
        shutil.rmtree(self.base_dir, ignore_errors=True)

    def _build_ca(self, name: str):
        ca_dir = os.path.join(self.base_dir, name)
        os.makedirs(ca_dir)
        ca_key = os.path.join(ca_dir, 'ca-key.pem')
        ca_cert = os.path.join(ca_dir, 'ca-cert.pem')
        signing_key = os.path.join(ca_dir, 'ca-signing-key.pem')
        pki.gen_private_key(ca_key, 'password')
        pki.remove_passphrase(ca_key, 'password', ca_key)
        pki.gen_public_key(
            ca_cert, ca_key, '', '/CN=%s' % name,
        )
        pki.gen_private_key(signing_key, 'password')
        pki.remove_passphrase(signing_key, 'password', signing_key)
        return ca_cert, ca_key, signing_key

    def _new_cache_dir(self, name: str) -> str:
        cache_dir = os.path.join(self.base_dir, name)
        os.makedirs(cache_dir)
        return cache_dir

    def _generator(self, ca_material):
        ca_cert, ca_key, signing_key = ca_material

        def generate(host, certificate, paths: LeafPaths) -> None:
            pki.gen_public_key(
                public_key_path=paths.pub,
                private_key_path=signing_key,
                private_key_password='',
                subject='/CN=%s' % host,
                alt_subj_names=[host],
            )
            pki.gen_csr(
                csr_path=paths.csr,
                key_path=signing_key,
                password='',
                crt_path=paths.pub,
            )
            pki.sign_csr(
                csr_path=paths.csr,
                crt_path=paths.pem,
                ca_key_path=ca_key,
                ca_key_password='',
                ca_crt_path=ca_cert,
                serial=str(int(time.time() * 1000)),
                alt_subj_names=[host],
            )
        return generate

    def _cache(self, cache_dir, ca_material, generator=None):
        ca_cert, ca_key, signing_key = ca_material
        return CertificateCache(
            cache_dir=cache_dir,
            ca_cert_file=ca_cert,
            ca_key_file=ca_key,
            signing_key_file=signing_key,
            generator=generator or self._generator(ca_material),
        )


class TestCertificateCache(CertCacheTestBase):

    def test_cold_miss_generates_full_entry(self) -> None:
        cache_dir = self._new_cache_dir('cold')
        cache = self._cache(cache_dir, self.ca_one)
        pem_path = cache.get('host-one.test', self.upstream_cert)
        self.assertEqual(
            pem_path,
            LeafPaths(cache_dir, 'host-one.test').pem,
        )
        for suffix in ('.pem', '.pub', '.csr', '.meta'):
            self.assertTrue(
                os.path.isfile(
                    os.path.join(cache_dir, 'host-one.test' + suffix),
                ),
            )
        self.assertTrue(cache._openssl_verifies(pem_path))

    def test_cache_hit_does_not_regenerate(self) -> None:
        cache_dir = self._new_cache_dir('hit')
        cache = self._cache(cache_dir, self.ca_one)
        first = cache.get('host-hit.test', self.upstream_cert)
        stat = os.stat(first)
        second = cache.get('host-hit.test', self.upstream_cert)
        self.assertEqual(first, second)
        self.assertEqual(os.stat(second).st_ino, stat.st_ino)
        self.assertEqual(os.stat(second).st_mtime_ns, stat.st_mtime_ns)

    def test_new_process_reuses_validated_cache(self) -> None:
        cache_dir = self._new_cache_dir('restart')
        first_cache = self._cache(cache_dir, self.ca_one)
        first_pem = first_cache.get('host-restart.test', self.upstream_cert)
        inode = os.stat(first_pem).st_ino
        # Simulate a brand new process: fresh instance, no in-memory memo.
        second_cache = self._cache(cache_dir, self.ca_one)
        second_pem = second_cache.get(
            'host-restart.test', self.upstream_cert,
        )
        self.assertEqual(second_pem, first_pem)
        self.assertEqual(os.stat(second_pem).st_ino, inode)

    def test_ca_rotation_forces_regeneration(self) -> None:
        cache_dir = self._new_cache_dir('rotate-ca')
        old_cache = self._cache(cache_dir, self.ca_one)
        old_pem = old_cache.get('host-rotate.test', self.upstream_cert)
        old_inode = os.stat(old_pem).st_ino
        new_cache = self._cache(cache_dir, self.ca_two)
        new_pem = new_cache.get(
            'host-rotate.test', self.upstream_cert,
        )
        self.assertEqual(new_pem, old_pem)
        self.assertNotEqual(os.stat(new_pem).st_ino, old_inode)
        # The replacement is signed by the new CA and rejected by the old.
        self.assertTrue(new_cache._openssl_verifies(new_pem))
        old_verifier = self._cache(cache_dir, self.ca_one)
        self.assertFalse(old_verifier._openssl_verifies(new_pem))

    def test_signing_key_rotation_forces_regeneration(self) -> None:
        cache_dir = self._new_cache_dir('rotate-signing')
        ca_cert, ca_key, old_signing = self.ca_one
        new_signing = os.path.join(self.base_dir, 'ca-one', 'new-signing.pem')
        pki.gen_private_key(new_signing, 'password')
        pki.remove_passphrase(new_signing, 'password', new_signing)

        old_cache = self._cache(cache_dir, self.ca_one)
        old_pem = old_cache.get('host-signing.test', self.upstream_cert)
        old_inode = os.stat(old_pem).st_ino

        rotated_material = (ca_cert, ca_key, new_signing)
        new_cache = self._cache(cache_dir, rotated_material)
        new_pem = new_cache.get(
            'host-signing.test', self.upstream_cert,
        )
        self.assertNotEqual(os.stat(new_pem).st_ino, old_inode)
        self.assertTrue(new_cache._public_key_matches(new_pem))
        self.assertFalse(old_cache._public_key_matches(new_pem))

    def test_corrupt_pem_is_regenerated(self) -> None:
        cache_dir = self._new_cache_dir('corrupt')
        cache = self._cache(cache_dir, self.ca_one)
        pem_path = cache.get('host-corrupt.test', self.upstream_cert)
        good_inode = os.stat(pem_path).st_ino
        with open(pem_path, 'wb') as broken:
            broken.write(b'this is definitely not a certificate')
        recovered = cache.get(
            'host-corrupt.test', self.upstream_cert,
        )
        self.assertNotEqual(os.stat(recovered).st_ino, good_inode)
        self.assertTrue(cache._openssl_verifies(recovered))

    def test_corrupt_sidecar_is_regenerated(self) -> None:
        cache_dir = self._new_cache_dir('corrupt-meta')
        cache = self._cache(cache_dir, self.ca_one)
        pem_path = cache.get('host-meta.test', self.upstream_cert)
        good_inode = os.stat(pem_path).st_ino
        with open(LeafPaths(cache_dir, 'host-meta.test').meta, 'wb') as meta:
            meta.write(b'garbage')
        # A fresh process has no in-memory memo and must discover the
        # damaged sidecar through on-disk validation.
        restarted_cache = self._cache(cache_dir, self.ca_one)
        recovered = restarted_cache.get(
            'host-meta.test', self.upstream_cert,
        )
        self.assertNotEqual(os.stat(recovered).st_ino, good_inode)

    def test_foreign_host_certificate_is_regenerated(self) -> None:
        cache_dir = self._new_cache_dir('identity')
        cache = self._cache(cache_dir, self.ca_one)
        source = cache.get('host-a.test', self.upstream_cert)
        source_inode = os.stat(source).st_ino
        # Plant host-a's material under host-b's file names.  A path-only
        # cache would wrongly load it; identity validation must reject it.
        source_paths = LeafPaths(cache_dir, 'host-a.test')
        foreign_paths = LeafPaths(cache_dir, 'host-b.test')
        for suffix in ('.pem', '.pub', '.csr', '.meta'):
            shutil.copy(
                getattr(source_paths, suffix[1:]),
                getattr(foreign_paths, suffix[1:]),
            )
        recovered = cache.get('host-b.test', self.upstream_cert)
        self.assertNotEqual(os.stat(recovered).st_ino, source_inode)
        certificate = cache._validate(foreign_paths, 'host-b.test')
        self.assertTrue(certificate[0])

    def test_failed_generation_leaves_no_usable_cache(self) -> None:
        cache_dir = self._new_cache_dir('failure')

        def failing_generator(host, certificate, paths):
            raise RuntimeError('simulated openssl failure')

        cache = self._cache(cache_dir, self.ca_one, failing_generator)
        with self.assertRaises(CertificateGenerationError):
            cache.get('host-fail.test', self.upstream_cert)
        paths = LeafPaths(cache_dir, 'host-fail.test')
        self.assertFalse(os.path.exists(paths.pem))
        self.assertFalse(os.path.exists(paths.pub))
        self.assertFalse(os.path.exists(paths.csr))
        self.assertFalse(os.path.exists(paths.meta))
        self.assertEqual(
            [n for n in os.listdir(cache_dir)
             if n.startswith('proxy-cert-')],
            [],
        )
        # A later, healthy attempt must not be poisoned by the failure.
        cache.generator = self._generator(self.ca_one)
        recovered = cache.get('host-fail.test', self.upstream_cert)
        self.assertTrue(os.path.isfile(recovered))

    def test_concurrent_same_host_generates_once(self) -> None:
        cache_dir = self._new_cache_dir('concurrent')
        call_count = {'n': 0}
        counter_lock = threading.Lock()
        real_generator = self._generator(self.ca_one)

        def slow_generator(host, certificate, paths):
            with counter_lock:
                call_count['n'] += 1
            time.sleep(0.1)
            real_generator(host, certificate, paths)

        cache = self._cache(cache_dir, self.ca_one, slow_generator)
        results = []
        results_lock = threading.Lock()

        def worker() -> None:
            pem = cache.get('host-concurrent.test', self.upstream_cert)
            with results_lock:
                results.append(pem)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(set(results)), 1)
        self.assertEqual(call_count['n'], 1)

    def test_concurrent_different_hosts_both_succeed(self) -> None:
        cache_dir = self._new_cache_dir('concurrent-multi')
        cache = self._cache(cache_dir, self.ca_one)
        results = {}
        results_lock = threading.Lock()

        def worker(host: str) -> None:
            pem = cache.get(host, self.upstream_cert)
            with results_lock:
                results[host] = pem

        threads = [
            threading.Thread(target=worker, args=('host-x.test',)),
            threading.Thread(target=worker, args=('host-y.test',)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(results), 2)
        for host, pem in results.items():
            self.assertTrue(os.path.isfile(pem))
            valid, _ = cache._validate(
                LeafPaths(cache_dir, host), host,
            )
            self.assertTrue(valid)

    def test_audit_classifies_valid_stale_and_corrupt(self) -> None:
        cache_dir = self._new_cache_dir('audit')
        ca_one_cache = self._cache(cache_dir, self.ca_one)
        ca_one_cache.get('stale-host.test', self.upstream_cert)
        ca_two_cache = self._cache(cache_dir, self.ca_two)
        ca_two_cache.get('fresh-host.test', self.upstream_cert)
        with open(
            LeafPaths(cache_dir, 'broken-host.test').pem, 'wb',
        ) as broken:
            broken.write(b'corrupt')
        report = ca_two_cache.audit()
        hosts = {
            bucket: {entry['host'] for entry in entries}
            for bucket, entries in report.items()
        }
        self.assertEqual(hosts['valid'], {'fresh-host.test'})
        self.assertEqual(hosts['stale'], {'stale-host.test'})
        self.assertEqual(hosts['corrupt'], {'broken-host.test'})

    def test_log_audit_scans_only_once_per_process(self) -> None:
        cache_dir = self._new_cache_dir('audit-once')
        cache = self._cache(cache_dir, self.ca_one)
        cache.get('host-audit.test', self.upstream_cert)
        with mock.patch.object(
            cache, 'audit', wraps=cache.audit,
        ) as audit_mock:
            cache.log_audit()
            cache.log_audit()
            cache.log_audit()
        self.assertEqual(audit_mock.call_count, 1)

    def test_configuration_warnings_for_missing_and_mismatched_material(
            self,
    ) -> None:
        cache_dir = self._new_cache_dir('warnings')
        ca_cert, ca_key, signing_key = self.ca_one
        missing_cache = CertificateCache(
            cache_dir=cache_dir,
            ca_cert_file=ca_cert,
            ca_key_file=os.path.join(self.base_dir, 'missing-key.pem'),
            signing_key_file=signing_key,
            generator=self._generator(self.ca_one),
        )
        self.assertTrue(
            any('missing' in w for w in missing_cache.configuration_warnings),
        )
        mismatched_cache = CertificateCache(
            cache_dir=self._new_cache_dir('warnings-mismatch'),
            ca_cert_file=ca_cert,
            # Passing the signing key where the CA key is expected.
            ca_key_file=signing_key,
            signing_key_file=signing_key,
            generator=self._generator(self.ca_one),
        )
        self.assertTrue(
            any('not a matching pair' in w
                for w in mismatched_cache.configuration_warnings),
        )

    def test_fingerprint_helpers_reject_corrupt_files(self) -> None:
        broken = os.path.join(self.base_dir, 'broken.pem')
        with open(broken, 'wb') as handle:
            handle.write(b'not a pem')
        self.assertIsNone(sha256_fingerprint(broken))
        self.assertIsNone(
            public_key_fingerprint(broken, 'x509', 5, 'openssl'),
        )
        self.assertIsNone(
            public_key_fingerprint(broken, 'rsa', 5, 'openssl'),
        )

    def test_expired_certificate_is_regenerated(self) -> None:
        from proxy.common import cert_cache
        cache_dir = self._new_cache_dir('expired')
        cache = self._cache(cache_dir, self.ca_one)
        pem_path = cache.get('host-expired.test', self.upstream_cert)
        good_inode = os.stat(pem_path).st_ino

        real_decode = cert_cache.decode_certificate
        expired_reported = {'done': False}

        def expired_decode(path):
            parsed = real_decode(path)
            if parsed is None or not path.endswith('host-expired.test.pem'):
                return parsed
            if not expired_reported['done']:
                expired_reported['done'] = True
                parsed = dict(parsed)
                parsed['notBefore'] = 'Jan  1 00:00:00 2020 GMT'
                parsed['notAfter'] = 'Jan  2 00:00:00 2020 GMT'
            return parsed

        with mock.patch.object(
            cert_cache, 'decode_certificate', side_effect=expired_decode,
        ):
            # The in-memory memo must not hide on-disk expiry from a new
            # process, so build a fresh cache instance for the check.
            restarted = self._cache(cache_dir, self.ca_one)
            recovered = restarted.get(
                'host-expired.test', self.upstream_cert,
            )
        self.assertNotEqual(os.stat(recovered).st_ino, good_inode)

    def test_unknown_sidecar_version_is_regenerated(self) -> None:
        cache_dir = self._new_cache_dir('sidecar-version')
        cache = self._cache(cache_dir, self.ca_one)
        pem_path = cache.get('host-version.test', self.upstream_cert)
        good_inode = os.stat(pem_path).st_ino
        meta_path = LeafPaths(cache_dir, 'host-version.test').meta
        with open(meta_path, 'r', encoding='utf-8') as handle:
            payload = handle.read().splitlines()
        payload[0] = '999'
        with open(meta_path, 'w', encoding='utf-8') as handle:
            handle.write('\n'.join(payload) + '\n')
        restarted = self._cache(cache_dir, self.ca_one)
        recovered = restarted.get(
            'host-version.test', self.upstream_cert,
        )
        self.assertNotEqual(os.stat(recovered).st_ino, good_inode)


class TestCertificateCacheCrossProcess(CertCacheTestBase):

    def test_flock_serializes_separate_processes(self) -> None:
        # fcntl is POSIX-only; the in-process lock registry covers the
        # other platforms.
        if os.name == 'nt':
            self.skipTest('flock based cross-process test is POSIX only')
        import subprocess
        import sys
        cache_dir = self._new_cache_dir('cross-process')
        worker = os.path.join(self.base_dir, 'worker.py')
        host = 'shared-host.test'
        with open(worker, 'w', encoding='utf-8') as handle:
            handle.write(
                '\n'.join((
                    'import sys, time',
                    'sys.path.insert(0, %r)' % os.getcwd(),
                    'from proxy.common.cert_cache import LeafPaths, _file_lock',
                    'cache_dir, marker, host = sys.argv[1:4]',
                    'paths = LeafPaths(cache_dir, host)',
                    'with _file_lock(paths.lock):',
                    '    open(marker, "w").write("locked")',
                    '    time.sleep(1)',
                )),
            )
        marker = os.path.join(self.base_dir, 'marker')
        proc = subprocess.Popen(
            [sys.executable, worker, cache_dir, marker, host],
        )
        deadline = time.time() + 5
        while not os.path.exists(marker) and time.time() < deadline:
            time.sleep(0.05)
        self.assertTrue(os.path.exists(marker))
        # While the worker holds the flock, acquiring it here blocks until
        # the worker exits; the elapsed time proves exclusivity.
        from proxy.common.cert_cache import _file_lock
        started = time.time()
        with _file_lock(LeafPaths(cache_dir, host).lock):
            waited = time.time() - started
        proc.wait(timeout=5)
        self.assertGreaterEqual(waited, 0.8)


class TestHttpProxyPluginCacheWiring(CertCacheTestBase):
    """Exercise the HttpProxyPlugin cache factory the same way the
    interception handler does, without requiring an asyncio event loop."""

    def setUp(self) -> None:
        super().setUp()
        from proxy.http.proxy import HttpProxyPlugin
        from proxy.http.exception import HttpProtocolException
        self.plugin_cls = HttpProxyPlugin
        self.http_exception = HttpProtocolException
        self.plugin_cls._cert_cache_instance = None
        self.cache_dir = self._new_cache_dir('plugin-wiring')
        self.flags = types.SimpleNamespace(
            ca_cert_dir=self.cache_dir,
            ca_cert_file=self.ca_one[0],
            ca_key_file=self.ca_one[1],
            ca_signing_key_file=self.ca_one[2],
            openssl='openssl',
        )
        self.plugin = self.plugin_cls.__new__(self.plugin_cls)
        self.plugin.flags = self.flags
        self.plugin.request = mock.MagicMock()
        self.plugin.request.host = b'wiring-host.test'

    def tearDown(self) -> None:
        self.plugin_cls._cert_cache_instance = None
        super().tearDown()

    def test_plugin_generates_then_reuses_cached_cert(self) -> None:
        first = self.plugin.generate_upstream_certificate(self.upstream_cert)
        self.assertTrue(os.path.isfile(first))
        inode = os.stat(first).st_ino
        second = self.plugin.generate_upstream_certificate(self.upstream_cert)
        self.assertEqual(os.stat(second).st_ino, inode)
        identity, cache = self.plugin_cls._cert_cache_instance
        self.assertIsInstance(cache, CertificateCache)
        self.assertEqual(
            identity,
            (self.ca_one[0], self.ca_one[1], self.ca_one[2]),
        )

    def test_plugin_rebuilds_cache_when_ca_material_rotates(self) -> None:
        old_pem = self.plugin.generate_upstream_certificate(self.upstream_cert)
        old_inode = os.stat(old_pem).st_ino
        old_cache = self.plugin_cls._cert_cache_instance[1]

        self.flags.ca_cert_file = self.ca_two[0]
        self.flags.ca_key_file = self.ca_two[1]
        self.flags.ca_signing_key_file = self.ca_two[2]
        new_pem = self.plugin.generate_upstream_certificate(self.upstream_cert)

        self.assertNotEqual(os.stat(new_pem).st_ino, old_inode)
        identity, new_cache = self.plugin_cls._cert_cache_instance
        self.assertEqual(identity, self.ca_two)
        self.assertIsNot(new_cache, old_cache)
        self.assertTrue(new_cache._openssl_verifies(new_pem))

    def test_plugin_raises_when_flags_incomplete(self) -> None:
        self.flags.ca_cert_file = None
        with self.assertRaises(self.http_exception):
            self.plugin.generate_upstream_certificate(self.upstream_cert)


if __name__ == '__main__':
    unittest.main()
