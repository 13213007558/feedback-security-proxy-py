# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    Proxy credential isolation tests.

    These tests assert that ``Proxy-Authorization`` (and other hop-by-hop
    headers) submitted by a client are only ever used for authentication
    against proxy.py itself and never leak towards origin servers or
    upstream proxies.

    All assertions are made against the *raw bytes captured on the fake
    upstream connection* (and not against the parser's internal header
    dictionary).  This way these tests also catch implementations where a
    header is deleted from the parsed data structure but silently
    re-introduced when the outbound packet is rebuilt (e.g. from a raw
    buffer kept aside by the parser).
"""
import base64
from typing import Any, List, Optional, cast

import pytest

from pytest_mock import MockerFixture

from proxy.http import HttpProtocolHandler, HttpClientConnection
from proxy.http.proxy import HttpProxyPlugin
from proxy.http.parser import HttpParser, httpParserTypes
from proxy.http.proxy.auth import AuthPlugin
from proxy.common.flag import FlagParser
from proxy.common.utils import build_http_request
from proxy.http.responses import PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT
from proxy.http.proxy.plugin import HttpProxyBasePlugin
from proxy.plugin import ProxyPoolPlugin


# base64('client:proxy-secret')
CLIENT_PROXY_SECRET = b'Y2xpZW50OnByb3h5LXNlY3JldA=='
CLIENT_PROXY_AUTH = b'Basic ' + CLIENT_PROXY_SECRET
# base64('first:secret') & base64('second:secret') for duplicate header tests
FIRST_PROXY_SECRET = b'Zmlyc3Q6c2VjcmV0'
SECOND_PROXY_SECRET = b'c2Vjb25kOnNlY3JldA=='
# A legitimate end-to-end credential which MUST reach the origin server
E2E_AUTH = b'Bearer end-to-end-token'
# Upstream proxy credentials, sourced from proxy pool configuration
UPSTREAM_PROXY_SECRET = base64.b64encode(b'upstream-user:upstream-pass')


def _assert_not_leaked(forwarded: bytes, *secrets: bytes) -> None:
    """Asserts that neither the header name (any case) nor the secret
    value appears anywhere within the raw forwarded bytes."""
    lowered = forwarded.lower()
    assert b'proxy-authorization' not in lowered, \
        'Proxy-Authorization header leaked upstream: %r' % forwarded
    assert b'proxy-connection' not in lowered, \
        'Proxy-Connection header leaked upstream: %r' % forwarded
    for secret in secrets:
        assert secret not in forwarded, \
            'credential %r leaked upstream: %r' % (secret, forwarded)


class _RecordingPlugin(HttpProxyBasePlugin):
    """Controlled plugin which records the credentials visible to
    in-proxy consumers (e.g. auth plugins) while requests are processed."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.proxy_auth_seen: Optional[bytes] = None

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        if request.has_header(b'proxy-authorization'):
            self.proxy_auth_seen = request.header(b'proxy-authorization')
        return request

    def handle_client_request(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        return request


class TestProxyCredentialIsolation:
    """Plain HTTP proxying: hop-by-hop credentials must be consumed
    locally and never dispatched to the origin server."""

    @pytest.fixture(autouse=True)   # type: ignore[misc]
    def _setUp(self, mocker: MockerFixture) -> None:
        self.mocker = mocker
        self.mock_server_conn = mocker.patch(
            'proxy.http.proxy.server.TcpServerConnection',
        )
        self.mock_selector = mocker.patch('selectors.DefaultSelector')
        self.mock_socket = mocker.patch('socket.socket')
        self.mock_socket_dup = mocker.patch('socket.dup')
        self.fileno = 10
        self.mock_socket_dup.side_effect = lambda fd: fd
        self._addr = ('127.0.0.1', 54382)
        self._conn = mocker.MagicMock()
        self.mock_socket.side_effect = \
            lambda **kwargs: self._conn if kwargs.get('fileno') == self.fileno else mocker.DEFAULT
        # Fake upstream must look open & usable
        self.mock_server_conn.return_value.closed = False

    def _initialize_handler(
            self,
            base_plugins: Optional[List[type]] = None,
            **flag_kwargs: Any,
    ) -> None:
        self.flags = FlagParser.initialize(threaded=True, **flag_kwargs)
        self.flags.plugins = {
            b'HttpProtocolHandlerPlugin': [HttpProxyPlugin],
            b'HttpProxyBasePlugin': base_plugins or [],
        }
        self.protocol_handler = HttpProtocolHandler(
            HttpClientConnection(self._conn, self._addr),
            flags=self.flags,
        )
        self.protocol_handler.initialize()

    def _upstream_queued_bytes(self) -> List[bytes]:
        """All raw byte chunks queued on the fake upstream connection."""
        return [
            bytes(call[0][0])
            for call in self.mock_server_conn.return_value.queue.call_args_list
        ]

    def _dispatch(self, *raw_requests: bytes) -> List[bytes]:
        for raw in raw_requests:
            self.protocol_handler.handle_data(memoryview(raw))
        return self._upstream_queued_bytes()

    def test_proxy_authorization_stripped_before_dispatch_to_upstream(self) -> None:
        self._initialize_handler()
        forwarded = self._dispatch(build_http_request(
            b'GET', b'http://upstream.host/get',
            headers={
                b'Host': b'upstream.host',
                b'Proxy-Authorization': CLIENT_PROXY_AUTH,
                b'Proxy-Connection': b'keep-alive',
            },
        ))
        assert len(forwarded) == 1
        _assert_not_leaked(forwarded[0], CLIENT_PROXY_SECRET)

    def test_proxy_authorization_header_name_is_case_insensitive(self) -> None:
        self._initialize_handler()
        forwarded = self._dispatch(
            b'GET http://upstream.host/get HTTP/1.1\r\n'
            b'Host: upstream.host\r\n'
            b'PrOxY-aUtHoRiZaTiOn: ' + CLIENT_PROXY_AUTH + b'\r\n'
            b'pRoXy-cOnNeCtIoN: keep-alive\r\n'
            b'\r\n',
        )
        assert len(forwarded) == 1
        _assert_not_leaked(forwarded[0], CLIENT_PROXY_SECRET)

    def test_duplicate_proxy_authorization_headers_never_leak(self) -> None:
        self._initialize_handler()
        forwarded = self._dispatch(
            b'GET http://upstream.host/get HTTP/1.1\r\n'
            b'Host: upstream.host\r\n'
            b'Proxy-Authorization: Basic ' + FIRST_PROXY_SECRET + b'\r\n'
            b'Proxy-Authorization: Basic ' + SECOND_PROXY_SECRET + b'\r\n'
            b'\r\n',
        )
        assert len(forwarded) == 1
        _assert_not_leaked(
            forwarded[0], FIRST_PROXY_SECRET, SECOND_PROXY_SECRET,
        )

    def test_connection_nominated_hop_by_hop_headers_stripped(self) -> None:
        """Headers nominated by the Connection header are hop-by-hop and
        must not be forwarded (RFC 7230 section 6.1)."""
        self._initialize_handler()
        forwarded = self._dispatch(build_http_request(
            b'GET', b'http://upstream.host/get',
            headers={
                b'Host': b'upstream.host',
                b'Connection': b'keep-alive, X-Hop-Token',
                b'X-Hop-Token': b'hop-by-hop-secret',
            },
        ))
        assert len(forwarded) == 1
        # Nominated header line is gone (the Connection header itself is
        # forwarded as-is, which is existing proxy.py behavior).
        assert b'X-Hop-Token:' not in forwarded[0]
        assert b'hop-by-hop-secret' not in forwarded[0]

    def test_end_to_end_authorization_header_preserved(self) -> None:
        """A legitimate end-to-end Authorization header MUST reach the
        origin server untouched."""
        self._initialize_handler()
        forwarded = self._dispatch(build_http_request(
            b'GET', b'http://upstream.host/get',
            headers={
                b'Host': b'upstream.host',
                b'Proxy-Authorization': CLIENT_PROXY_AUTH,
                b'Authorization': E2E_AUTH,
            },
        ))
        assert len(forwarded) == 1
        _assert_not_leaked(forwarded[0], CLIENT_PROXY_SECRET)
        assert b'Authorization: ' + E2E_AUTH in forwarded[0]

    def test_custom_disable_headers_still_strip_proxy_authorization(self) -> None:
        """Custom --disable-headers must be honored AND proxy credentials
        must be stripped independently of the disable_headers config."""
        self._initialize_handler(disable_headers=[b'x-internal-token'])
        forwarded = self._dispatch(build_http_request(
            b'GET', b'http://upstream.host/get',
            headers={
                b'Host': b'upstream.host',
                b'Proxy-Authorization': CLIENT_PROXY_AUTH,
                b'X-Internal-Token': b'internal-secret',
            },
        ))
        assert len(forwarded) == 1
        _assert_not_leaked(forwarded[0], CLIENT_PROXY_SECRET)
        assert b'X-Internal-Token' not in forwarded[0]
        assert b'internal-secret' not in forwarded[0]

    def test_plugin_consumes_credentials_but_upstream_never_sees_them(self) -> None:
        """In-proxy consumers (e.g. auth plugins) can read the credential
        while it must still be absent from the dispatched bytes."""
        self._initialize_handler(base_plugins=[_RecordingPlugin])
        forwarded = self._dispatch(build_http_request(
            b'GET', b'http://upstream.host/get',
            headers={
                b'Host': b'upstream.host',
                b'Proxy-Authorization': CLIENT_PROXY_AUTH,
            },
        ))
        proxy_plugin = cast(HttpProxyPlugin, self.protocol_handler.plugin)
        plugin = cast(
            _RecordingPlugin, proxy_plugin.plugins['_RecordingPlugin'],
        )
        # Credential was available for this hop's authentication ...
        assert plugin.proxy_auth_seen == CLIENT_PROXY_AUTH
        # ... but never left the proxy towards the origin server.
        assert len(forwarded) == 1
        _assert_not_leaked(forwarded[0], CLIENT_PROXY_SECRET)

    def test_valid_authenticated_credentials_not_forwarded(self) -> None:
        """With proxy auth enabled, successfully validated credentials are
        consumed by the auth plugin and must not flow to the origin."""
        self._initialize_handler(
            base_plugins=[AuthPlugin],
            auth_code=CLIENT_PROXY_SECRET,
        )
        forwarded = self._dispatch(build_http_request(
            b'GET', b'http://upstream.host/get',
            headers={
                b'Host': b'upstream.host',
                b'Proxy-Authorization': CLIENT_PROXY_AUTH,
            },
        ))
        assert len(forwarded) == 1
        _assert_not_leaked(forwarded[0], CLIENT_PROXY_SECRET)

    def test_keep_alive_follow_up_request_is_sanitized(self) -> None:
        """Requests pipelined over the same keep-alive connection must
        receive the same sanitization as the first request."""
        self._initialize_handler(disable_headers=[b'x-internal-token'])
        forwarded = self._dispatch(
            build_http_request(
                b'GET', b'http://upstream.host/first',
                headers={b'Host': b'upstream.host'},
            ),
            build_http_request(
                b'GET', b'/second',
                headers={
                    b'Host': b'upstream.host',
                    b'Proxy-Authorization': CLIENT_PROXY_AUTH,
                    b'Proxy-Connection': b'keep-alive',
                    b'Connection': b'keep-alive, X-Hop-Token',
                    b'X-Hop-Token': b'hop-by-hop-secret',
                    b'X-Internal-Token': b'internal-secret',
                    b'Authorization': E2E_AUTH,
                },
            ),
        )
        assert len(forwarded) == 2
        _assert_not_leaked(forwarded[1], CLIENT_PROXY_SECRET)
        assert b'X-Hop-Token:' not in forwarded[1]
        assert b'hop-by-hop-secret' not in forwarded[1]
        assert b'X-Internal-Token' not in forwarded[1]
        assert b'internal-secret' not in forwarded[1]
        assert b'Authorization: ' + E2E_AUTH in forwarded[1]

    def test_connect_request_never_forwarded_and_tunnel_bytes_untouched(self) -> None:
        """CONNECT response phase and post-tunnel bytes must not be mixed:

        1) The CONNECT request (incl. its Proxy-Authorization) is never
           dispatched to the upstream server.
        2) Client receives the tunnel established response.
        3) Bytes sent after tunnel establishment are opaque payload and
           must be forwarded verbatim, even if they look like headers.
        """
        self._initialize_handler()
        forwarded = self._dispatch(
            b'CONNECT secure.host:443 HTTP/1.1\r\n'
            b'Host: secure.host:443\r\n'
            b'Proxy-Authorization: ' + CLIENT_PROXY_AUTH + b'\r\n'
            b'\r\n',
        )
        # CONNECT request itself never reached the upstream server
        assert forwarded == []
        # Client got the tunnel established response
        assert self.protocol_handler.work.has_buffer()
        assert bytes(
            self.protocol_handler.work.buffer[0],
        ) == bytes(PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT)
        # Opaque tunnel payload is forwarded verbatim ...
        tunnel_payload = \
            b'\x16\x03\x01Proxy-Authorization: ' + CLIENT_PROXY_AUTH + b'\x00\xff'
        forwarded = self._dispatch(tunnel_payload)
        assert forwarded == [tunnel_payload]

    def test_intercepted_https_request_is_sanitized(self) -> None:
        """Requests decrypted within a TLS intercepted tunnel must be
        sanitized exactly like plain HTTP proxy requests."""
        self.flags = FlagParser.initialize(
            threaded=True,
            ca_key_file='ca.key',
            ca_cert_file='ca.pem',
            ca_signing_key_file='ca-signing.key',
            disable_headers=[b'x-internal-token'],
        )
        self.flags.plugins = {b'HttpProxyBasePlugin': []}
        plugin = HttpProxyPlugin(
            'test-uid',
            self.flags,
            self.mocker.MagicMock(),
            HttpParser(httpParserTypes.REQUEST_PARSER),
        )
        # Simulate an established CONNECT tunnel with TLS interception on
        plugin.request.parse(memoryview(
            b'CONNECT secure.host:443 HTTP/1.1\r\n'
            b'Host: secure.host:443\r\n'
            b'\r\n',
        ))
        assert plugin.request.is_complete
        assert plugin.request.is_https_tunnel
        assert plugin._tls_intercept_enabled
        plugin.upstream = self.mocker.MagicMock()
        plugin.upstream.closed = False
        # Decrypted request within the intercepted tunnel
        plugin.on_client_data(memoryview(build_http_request(
            b'GET', b'/',
            headers={
                b'Host': b'secure.host',
                b'Proxy-Authorization': CLIENT_PROXY_AUTH,
                b'Proxy-Connection': b'keep-alive',
                b'X-Internal-Token': b'internal-secret',
                b'Authorization': E2E_AUTH,
            },
        )))
        assert plugin.upstream.queue.call_count == 1
        forwarded = bytes(plugin.upstream.queue.call_args[0][0])
        _assert_not_leaked(forwarded, CLIENT_PROXY_SECRET)
        assert b'X-Internal-Token' not in forwarded
        assert b'internal-secret' not in forwarded
        assert b'Authorization: ' + E2E_AUTH in forwarded


class TestUpstreamProxyCredentialIsolation:
    """When proxy.py itself proxies via an upstream proxy (proxy pool),
    the upstream proxy credentials must come from proxy.py's own
    configuration, never from credentials submitted by the client."""

    @pytest.fixture(autouse=True)   # type: ignore[misc]
    def _setUp(self, mocker: MockerFixture) -> None:
        self.mocker = mocker
        self.mock_initialize_upstream = mocker.patch.object(
            ProxyPoolPlugin, 'initialize_upstream',
        )
        self.flags = FlagParser.initialize(threaded=True)

    def _make_plugin(self, endpoint: str) -> ProxyPoolPlugin:
        self.flags.proxy_pool = [[endpoint]]
        plugin = ProxyPoolPlugin(
            'test-uid',
            self.flags,
            self.mocker.MagicMock(),
            self.mocker.MagicMock(),
        )
        upstream = self.mocker.MagicMock()

        def initialize_upstream(addr: str, port: int) -> None:
            plugin.upstream = upstream

        self.mock_initialize_upstream.side_effect = initialize_upstream
        return plugin

    def _dispatch(self, plugin: ProxyPoolPlugin, raw: bytes) -> bytes:
        request = HttpParser.request(raw)
        assert plugin.before_upstream_connection(request) is None
        plugin.handle_client_request(request)
        assert plugin.upstream is not None
        assert plugin.upstream.queue.call_count == 1
        return bytes(plugin.upstream.queue.call_args[0][0])

    def test_upstream_proxy_uses_configured_endpoint_credentials(self) -> None:
        plugin = self._make_plugin('upstream-user:upstream-pass@127.0.0.1:9000')
        forwarded = self._dispatch(
            plugin,
            build_http_request(
                b'GET', b'http://example.com/get',
                headers={
                    b'Host': b'example.com',
                    b'Proxy-Authorization': CLIENT_PROXY_AUTH,
                },
            ),
        )
        # Upstream proxy receives credentials sourced from configuration
        assert b'proxy-authorization: basic ' in forwarded.lower()
        assert UPSTREAM_PROXY_SECRET in forwarded
        # ... and never the credentials submitted by the client
        assert CLIENT_PROXY_SECRET not in forwarded

    def test_client_credentials_not_forwarded_to_upstream_proxy(self) -> None:
        """Without configured endpoint credentials, the client's
        Proxy-Authorization must not leak to the upstream proxy either."""
        plugin = self._make_plugin('127.0.0.1:9000')
        forwarded = self._dispatch(
            plugin,
            build_http_request(
                b'GET', b'http://example.com/get',
                headers={
                    b'Host': b'example.com',
                    b'Proxy-Authorization': CLIENT_PROXY_AUTH,
                    b'Proxy-Connection': b'keep-alive',
                },
            ),
        )
        _assert_not_leaked(forwarded, CLIENT_PROXY_SECRET)

    def test_client_credentials_not_forwarded_within_connect(self) -> None:
        """CONNECT requests relayed to an upstream proxy must not carry
        the credentials the client submitted to proxy.py."""
        plugin = self._make_plugin('127.0.0.1:9000')
        forwarded = self._dispatch(
            plugin,
            b'CONNECT example.com:443 HTTP/1.1\r\n'
            b'Host: example.com:443\r\n'
            b'Proxy-Authorization: ' + CLIENT_PROXY_AUTH + b'\r\n'
            b'\r\n',
        )
        _assert_not_leaked(forwarded, CLIENT_PROXY_SECRET)
