# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import asyncio
import select
import socket
import tempfile
import unittest
from typing import List, Optional
from unittest import mock

from proxy.http import HttpProtocolHandler, HttpClientConnection
from proxy.http.proxy import HttpProxyPlugin
from proxy.http.exception import HttpRequestRejected
from proxy.common.flag import FlagParser
from proxy.core.connection import TcpServerConnection
from proxy.http.responses import PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT


CONNECT_REQUEST = (
    b'CONNECT example.com:443 HTTP/1.1\r\n'
    b'Host: example.com:443\r\n'
    b'User-Agent: test-client\r\n'
    b'\r\n'
)

# A fake but binary TLS ClientHello record, including NUL and high bytes.
CLIENT_HELLO = b'\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03' + \
    bytes(range(256)) * 2

MORE_TUNNEL_DATA = b'\x17\x03\x03\x00\x20' + bytes(reversed(range(256))) + \
    b'\x00\xff\x00'


class _NonPeekableConn:
    """A client connection double which cannot be peeked into.

    Only the subset of the socket API used by the core is provided.
    Since it is not a `socket.socket` instance, the protocol handler
    must fall back to consuming data directly from it."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def recv(self, size: int, flags: int = 0) -> bytes:
        assert flags == 0, 'must not peek through a non-peekable connection'
        return self._sock.recv(size)

    def send(self, data: bytes) -> int:
        return self._sock.send(data)

    def fileno(self) -> int:
        return self._sock.fileno()

    def setblocking(self, flag: bool) -> None:
        self._sock.setblocking(flag)

    def shutdown(self, how: int) -> None:
        self._sock.shutdown(how)

    def close(self) -> None:
        self._sock.close()


class TestHttpProxyConnectTunnel(unittest.TestCase):
    """CONNECT requests coalesced with subsequent tunnel bytes (e.g. a
    TLS ClientHello) within the same TCP packet(s).

    Uses socket pairs as connection doubles with controllable read/write
    boundaries, and asserts both the bytes replied to the client and the
    exact stream received by the upstream server."""

    def setUp(self) -> None:
        self.client_server, self.client_peer = socket.socketpair()
        self.upstream_server, self.upstream_peer = socket.socketpair()
        self.client_server.setblocking(False)
        self.upstream_server.setblocking(False)
        self.data_dir = tempfile.mkdtemp()
        self.flags = FlagParser.initialize(
            [
                '--data-dir', self.data_dir,
                '--ca-cert-dir', self.data_dir,
                '--cache-dir', self.data_dir,
            ],
            threaded=True,
        )
        self.flags.plugins = {
            b'HttpProtocolHandlerPlugin': [HttpProxyPlugin],
        }
        # Upstream connection double backed by a real socket pair,
        # so that queue/flush semantics stay intact.
        self.upstream = TcpServerConnection('example.com', 443)
        self.upstream._conn = self.upstream_server
        self.upstream.closed = False
        self.upstream.connect = lambda **kwargs: None     # type: ignore[method-assign]
        self.tcp_server_connection = mock.patch(
            'proxy.http.proxy.server.TcpServerConnection',
            return_value=self.upstream,
        )
        self.mock_tcp_server_connection = self.tcp_server_connection.start()
        self.handler: Optional[HttpProtocolHandler] = None

    def tearDown(self) -> None:
        self.tcp_server_connection.stop()
        for sock in (
            self.client_server, self.client_peer,
            self.upstream_server, self.upstream_peer,
        ):
            try:
                sock.close()
            except OSError:
                pass

    #
    # Helpers
    #

    def _make_handler(self, peekable: bool = True) -> HttpProtocolHandler:
        conn = self.client_server if peekable else _NonPeekableConn(
            self.client_server,
        )
        self.handler = HttpProtocolHandler(
            HttpClientConnection(conn, ('127.0.0.1', 54382)),   # type: ignore[arg-type]
            flags=self.flags,
        )
        self.handler.initialize()
        return self.handler

    def _mock_base_plugin(self) -> mock.MagicMock:
        plugin = mock.MagicMock()
        plugin.return_value.get_descriptors = mock.AsyncMock(
            return_value=([], []),
        )
        plugin.return_value.write_to_descriptors = mock.AsyncMock(
            return_value=False,
        )
        plugin.return_value.read_from_descriptors = mock.AsyncMock(
            return_value=False,
        )
        self.flags.plugins[b'HttpProxyBasePlugin'] = [plugin]
        return plugin

    def _drive(
            self,
            readables: Optional[List[int]] = None,
            writables: Optional[List[int]] = None,
    ) -> bool:
        assert self.handler is not None
        return asyncio.run(
            self.handler.handle_events(readables or [], writables or []),
        )

    def _client_fileno(self) -> int:
        return self.client_server.fileno()

    def _upstream_fileno(self) -> int:
        return self.upstream_server.fileno()

    def _read_from_client(self) -> bool:
        return self._drive(readables=[self._client_fileno()])

    def _flush_pending(self) -> bool:
        return self._drive(
            writables=[self._client_fileno(), self._upstream_fileno()],
        )

    def _recv_exact(self, sock: socket.socket, size: int) -> bytes:
        sock.settimeout(5.0)
        data = b''
        try:
            while len(data) < size:
                chunk = sock.recv(size - len(data))
                if not chunk:
                    break
                data += chunk
        finally:
            sock.settimeout(None)
            sock.setblocking(False)
        return data

    def _recv_available(self, sock: socket.socket) -> bytes:
        sock.settimeout(1.0)
        data = b''
        try:
            while True:
                try:
                    chunk = sock.recv(65536)
                except (BlockingIOError, TimeoutError):
                    break
                if not chunk:
                    break
                data += chunk
        finally:
            sock.settimeout(None)
            sock.setblocking(False)
        return data

    def _assert_nothing_to_read(self, sock: socket.socket) -> None:
        sock.setblocking(False)
        try:
            self.assertEqual(sock.recv(1), b'')
        except BlockingIOError:
            pass

    def _assert_client_received_200(self) -> None:
        self.assertEqual(
            self._recv_exact(
                self.client_peer, len(PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT),
            ),
            bytes(PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT),
        )

    #
    # Tests
    #

    def test_coalesced_client_hello_tunneled_exactly_once(self) -> None:
        self._make_handler()
        # Client writes CONNECT headers and the first TLS ClientHello
        # within a single write, without waiting for the 200 response.
        self.client_peer.sendall(CONNECT_REQUEST + CLIENT_HELLO)
        self.assertFalse(self._read_from_client())
        # Tunnel establishment is announced to the client...
        self._flush_pending()
        self._assert_client_received_200()
        # ...but nothing was sent upstream before the tunnel was established.
        self._assert_nothing_to_read(self.upstream_peer)
        # The coalesced ClientHello is delivered upstream exactly once,
        # byte-identical and in order.
        self.assertFalse(self._read_from_client())
        self._flush_pending()
        self.assertEqual(
            self._recv_exact(self.upstream_peer, len(CLIENT_HELLO)),
            CLIENT_HELLO,
        )
        self._assert_nothing_to_read(self.upstream_peer)
        self._assert_nothing_to_read(self.client_peer)
        # Subsequent tunnel data keeps flowing, verbatim and in order.
        self.client_peer.sendall(MORE_TUNNEL_DATA)
        self.assertFalse(self._read_from_client())
        self._flush_pending()
        self.assertEqual(
            self._recv_exact(self.upstream_peer, len(MORE_TUNNEL_DATA)),
            MORE_TUNNEL_DATA,
        )
        self._assert_nothing_to_read(self.upstream_peer)
        self._assert_nothing_to_read(self.client_peer)

    def test_fragmented_headers_with_coalesced_client_hello(self) -> None:
        # Header bytes trickle in arbitrarily fragmented around the header
        # boundary; the ClientHello arrives coalesced with the final
        # header fragment.
        for split_at in (
            0,
            1,
            len(CONNECT_REQUEST) // 2,
            len(CONNECT_REQUEST) - 4,
            len(CONNECT_REQUEST) - 3,
            len(CONNECT_REQUEST) - 2,
            len(CONNECT_REQUEST) - 1,
            len(CONNECT_REQUEST),
        ):
            with self.subTest(split_at=split_at):
                self.tearDown()
                self.setUp()
                self._make_handler()
                self.client_peer.sendall(CONNECT_REQUEST[:split_at])
                self.assertFalse(self._read_from_client())
                # Nothing may go upstream before the tunnel is established
                self._assert_nothing_to_read(self.upstream_peer)
                self.client_peer.sendall(
                    CONNECT_REQUEST[split_at:] + CLIENT_HELLO,
                )
                self.assertFalse(self._read_from_client())
                # Still nothing flushed upstream
                self._assert_nothing_to_read(self.upstream_peer)
                self._flush_pending()
                self._assert_client_received_200()
                # Drain any coalesced ClientHello bytes into the tunnel
                if select.select([self.client_server], [], [], 0)[0]:
                    self.assertFalse(self._read_from_client())
                    self._flush_pending()
                self.assertEqual(
                    self._recv_exact(self.upstream_peer, len(CLIENT_HELLO)),
                    CLIENT_HELLO,
                )
                self._assert_nothing_to_read(self.upstream_peer)
                self._assert_nothing_to_read(self.client_peer)

    def test_plugin_rejection_never_forwards_peeked_bytes(self) -> None:
        plugin = self._mock_base_plugin()
        plugin.return_value.before_upstream_connection.side_effect = \
            HttpRequestRejected(
                status_code=403, reason=b'Denied', body=b'denied',
            )
        self._make_handler()
        self.client_peer.sendall(CONNECT_REQUEST + CLIENT_HELLO)
        # Reads are teared down after the rejection response has been flushed
        self._read_from_client()
        self._flush_pending()
        # Client receives the rejection response
        response = self._recv_available(self.client_peer)
        self.assertIn(b'403', response)
        self.assertIn(b'denied', response)
        # Upstream connection was never established and the coalesced
        # ClientHello was never forwarded anywhere.
        self.mock_tcp_server_connection.assert_not_called()
        assert self.handler is not None and self.handler.plugin is not None
        self.assertIsNone(self.handler.plugin.upstream)
        self._assert_nothing_to_read(self.upstream_peer)

    def test_plugin_veto_never_forwards_peeked_bytes(self) -> None:
        plugin = self._mock_base_plugin()
        # before_upstream_connection returning None vetoes the upstream
        # connection establishment.
        plugin.return_value.before_upstream_connection.return_value = None
        plugin.return_value.handle_client_request.side_effect = lambda r: r
        self._make_handler()
        self.client_peer.sendall(CONNECT_REQUEST + CLIENT_HELLO)
        self.assertFalse(self._read_from_client())
        self._flush_pending()
        # No tunnel was established, no bytes went out in either direction.
        self.mock_tcp_server_connection.assert_not_called()
        assert self.handler is not None and self.handler.plugin is not None
        self.assertIsNone(self.handler.plugin.upstream)
        self._assert_nothing_to_read(self.client_peer)
        self._assert_nothing_to_read(self.upstream_peer)

    def test_tls_interception_finds_client_hello_on_socket(self) -> None:
        # With TLS interception enabled, the coalesced ClientHello must
        # remain pending within the client socket buffer when the
        # interception handshake begins, i.e. the proxy must not have
        # consumed it while parsing the CONNECT request.
        self.flags.ca_key_file = 'ca.key'
        self.flags.ca_cert_dir = 'ca-cert-dir'
        self.flags.ca_signing_key_file = 'ca-signing.key'
        self.flags.ca_cert_file = 'ca.crt'
        self._make_handler()
        peeked_during_intercept = []

        def fake_intercept(plugin_self: HttpProxyPlugin) -> bool:
            peeked_during_intercept.append(
                self.client_server.recv(65536, socket.MSG_PEEK),
            )
            return False

        self.client_peer.sendall(CONNECT_REQUEST + CLIENT_HELLO)
        with mock.patch.object(
            HttpProxyPlugin, 'intercept', autospec=True,
            side_effect=fake_intercept,
        ):
            self.assertFalse(self._read_from_client())
        # The interception handshake would have found exactly the
        # ClientHello (and nothing else) at the head of the socket buffer.
        self.assertEqual(peeked_during_intercept, [CLIENT_HELLO])
        self._flush_pending()
        self._assert_client_received_200()
        # ClientHello was not leaked upstream either.
        self._assert_nothing_to_read(self.upstream_peer)

    def test_non_peekable_connection_delivers_leftover_exactly_once(self) -> None:
        # Fallback path for connections which cannot be peeked (e.g. TLS
        # wrapped client connections): bytes coalesced with the request
        # are held back within the parser buffer and must be delivered
        # to the tunnel exactly once.
        self._make_handler(peekable=False)
        self.client_peer.sendall(CONNECT_REQUEST + CLIENT_HELLO)
        self.assertFalse(self._read_from_client())
        self._flush_pending()
        self._assert_client_received_200()
        self.assertEqual(
            self._recv_exact(self.upstream_peer, len(CLIENT_HELLO)),
            CLIENT_HELLO,
        )
        self._assert_nothing_to_read(self.upstream_peer)
        self._assert_nothing_to_read(self.client_peer)
        # Subsequent tunnel data keeps flowing, verbatim and in order.
        self.client_peer.sendall(MORE_TUNNEL_DATA)
        self.assertFalse(self._read_from_client())
        self._flush_pending()
        self.assertEqual(
            self._recv_exact(self.upstream_peer, len(MORE_TUNNEL_DATA)),
            MORE_TUNNEL_DATA,
        )
        self._assert_nothing_to_read(self.upstream_peer)
        self._assert_nothing_to_read(self.client_peer)


if __name__ == '__main__':
    unittest.main()
