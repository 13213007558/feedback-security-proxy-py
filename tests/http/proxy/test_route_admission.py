# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    Tests for the final route admission phase.

    Two controlled plugins are used together:

    - ``RoutePolicyPlugin`` authorizes (or rejects) the exact host:port it is
      asked about and records every admission decision.
    - ``RouteRewriterPlugin`` rewrites the request destination from a chosen
      lifecycle hook, simulating a plugin that changes where traffic goes.

    A recording fake stands in for ``TcpServerConnection`` so the tests can
    assert the real (host, port) the core attempted to connect to.  The goal is
    to prove authorization always lands on the actually connected destination,
    independently of plugin ordering.
"""
import asyncio
import selectors
from typing import Any, List, Optional, Tuple

import pytest
from unittest import mock

from pytest_mock import MockerFixture

from proxy.http import HttpProtocolHandler, HttpClientConnection, httpStatusCodes
from proxy.http.proxy import HttpProxyPlugin, HttpProxyBasePlugin
from proxy.common.flag import FlagParser
from proxy.common.utils import build_http_request, build_http_response
from proxy.http.parser import HttpParser, httpParserTypes
from proxy.http.responses import PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT
from proxy.http.exception import (
    HttpRequestRejected, RouteAuthorizationRejected,
)


class FakeServerConnection:
    """Records the real connection parameters instead of opening a socket."""

    connects: List[Tuple[str, int]] = []

    def __init__(self, host: str, port: int) -> None:
        self.addr = (host, port)
        self.closed = True
        self.connection = mock.MagicMock()
        self.connection.fileno.return_value = 20
        self._queued: List[memoryview] = []

    def connect(
            self,
            addr: Optional[Tuple[str, int]] = None,
            source_address: Optional[Tuple[str, int]] = None,
    ) -> None:
        target = addr or self.addr
        FakeServerConnection.connects.append((target[0], target[1]))
        self.closed = False

    def setblocking(self, _flag: bool) -> None:
        pass

    def queue(self, data: memoryview) -> None:
        self._queued.append(data)

    def has_buffer(self) -> bool:
        return bool(self._queued)

    def flush(self, _max_size: int) -> None:
        self._queued.clear()

    def close(self) -> None:
        self.closed = True


class RoutePolicyPlugin(HttpProxyBasePlugin):
    """Destination based admission policy shared across the test cases."""

    # host:port tuples that must always be denied
    denied: List[Tuple[bytes, int]] = []
    # Every (host, port) tuple passed through authorize_route, in order.
    decisions: List[Tuple[bytes, int]] = []
    # When True, rejection is signalled by returning False instead of raising.
    return_false: bool = False

    def authorize_route(
            self, request: HttpParser,
    ) -> Optional[bool]:
        route = (request.host or b'', request.port or 0)
        RoutePolicyPlugin.decisions.append(route)
        if route in RoutePolicyPlugin.denied:
            if RoutePolicyPlugin.return_false:
                return False
            raise HttpRequestRejected(
                status_code=httpStatusCodes.FORBIDDEN,
                reason=b'Blocked by policy',
            )
        return True


class RouteRewriterPlugin(HttpProxyBasePlugin):
    """Rewrites the request destination from a configurable hook."""

    # Destination to rewrite to, or None to leave the request untouched.
    rewrite_to: Optional[Tuple[bytes, int]] = None
    # Lifecycle hook performing the rewrite.
    hook: str = 'before_upstream_connection'

    def _rewrite(self, request: HttpParser) -> HttpParser:
        if RouteRewriterPlugin.rewrite_to is not None:
            host, port = RouteRewriterPlugin.rewrite_to
            request.host = host
            request.port = port
        return request

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        if RouteRewriterPlugin.hook == 'before_upstream_connection':
            return self._rewrite(request)
        return request

    def handle_client_request(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        if RouteRewriterPlugin.hook == 'handle_client_request':
            return self._rewrite(request)
        return request


class ShortCircuitPlugin(HttpProxyBasePlugin):
    """Answers directly without an upstream connection (cache style plugin)."""

    short_circuit: bool = False

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        if ShortCircuitPlugin.short_circuit:
            return None
        return request

    def handle_client_request(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        if ShortCircuitPlugin.short_circuit:
            self.client.queue(
                memoryview(
                    build_http_response(
                        status_code=httpStatusCodes.OK,
                        reason=b'OK',
                        body=b'cached',
                    ),
                ),
            )
            return None
        return request


def _http_request(host: bytes, port: int) -> bytes:
    return build_http_request(
        b'GET',
        b'http://%s:%d/' % (host, port),
        headers={b'Host': b'%s:%d' % (host, port)},
        no_ua=True,
    )


def _connect_request(host: bytes, port: int) -> bytes:
    return build_http_request(
        b'CONNECT',
        b'%s:%d' % (host, port),
        headers={b'Host': b'%s:%d' % (host, port)},
        no_ua=True,
    )


class TestRouteAdmission:

    @pytest.fixture(autouse=True)   # type: ignore[misc]
    def _setUp(self, mocker: MockerFixture, tmp_path: Any) -> None:
        FakeServerConnection.connects = []
        RoutePolicyPlugin.denied = []
        RoutePolicyPlugin.decisions = []
        RoutePolicyPlugin.return_false = False
        RouteRewriterPlugin.rewrite_to = None
        RouteRewriterPlugin.hook = 'before_upstream_connection'
        ShortCircuitPlugin.short_circuit = False

        self._real_selector = selectors.DefaultSelector
        self.mock_socket = mocker.patch('socket.socket')
        self.mock_socket_dup = mocker.patch(
            'socket.dup', side_effect=lambda fd: fd,
        )
        self.mock_selector = mocker.patch('selectors.DefaultSelector')
        self.mock_server_conn = mocker.patch(
            'proxy.http.proxy.server.TcpServerConnection',
            side_effect=FakeServerConnection,
        )

        self._use_real_selector = False

        def _selector_factory() -> Any:
            if self._use_real_selector:
                return self._real_selector()
            return self.mock_selector.return_value

        self.mock_selector.side_effect = _selector_factory

        self._addr = ('127.0.0.1', 54382)
        self.data_dir = str(tmp_path)
        self.flags = FlagParser.initialize(
            input_args=['--cache-dir', str(tmp_path / 'cache')],
            threaded=True,
            data_dir=self.data_dir,
        )
        self.flags.plugins = {
            b'HttpProtocolHandlerPlugin': [HttpProxyPlugin],
            b'HttpProxyBasePlugin': [
                RoutePolicyPlugin, RouteRewriterPlugin, ShortCircuitPlugin,
            ],
        }
        self._conn = self.mock_socket.return_value
        self.protocol_handler = HttpProtocolHandler(
            HttpClientConnection(self._conn, self._addr),
            flags=self.flags,
        )
        self.protocol_handler.initialize()

    def _run_once(self) -> None:
        self.mock_selector.return_value.select.side_effect = [
            [(
                selectors.SelectorKey(
                    fileobj=self._conn.fileno(),
                    fd=self._conn.fileno(),
                    events=selectors.EVENT_READ,
                    data=None,
                ),
                selectors.EVENT_READ,
            )],
        ]
        # asyncio.run() needs a real selector for its event loop; the handler
        # itself uses the mocked DefaultSelector captured at construction time.
        self._use_real_selector = True
        try:
            asyncio.run(self.protocol_handler._run_once())
        finally:
            self._use_real_selector = False

    def test_admitted_route_is_connected(self) -> None:
        self._conn.recv.return_value = _http_request(b'allowed.example', 8080)
        self._run_once()

        assert FakeServerConnection.connects == [('allowed.example', 8080)]
        assert RoutePolicyPlugin.decisions == [(b'allowed.example', 8080)]
        self.mock_server_conn.assert_called_once_with('allowed.example', 8080)

    def test_denied_route_never_connects(self) -> None:
        RoutePolicyPlugin.denied = [(b'denied.example', 8080)]
        self._conn.recv.return_value = _http_request(b'denied.example', 8080)
        self._run_once()

        assert FakeServerConnection.connects == []
        self.mock_server_conn.assert_not_called()
        assert RoutePolicyPlugin.decisions == [(b'denied.example', 8080)]
        assert self.protocol_handler.work.buffer[0] == build_http_response(
            status_code=httpStatusCodes.FORBIDDEN,
            reason=b'Blocked by policy',
            conn_close=True,
        )

    def test_denied_route_via_false_return(self) -> None:
        RoutePolicyPlugin.return_false = True
        RoutePolicyPlugin.denied = [(b'denied.example', 80)]
        self._conn.recv.return_value = _http_request(b'denied.example', 80)
        self._run_once()

        assert FakeServerConnection.connects == []
        self.mock_server_conn.assert_not_called()
        response = HttpParser(httpParserTypes.RESPONSE_PARSER)
        response.parse(self.protocol_handler.work.buffer[0])
        assert int(response.code) == httpStatusCodes.FORBIDDEN

    def test_connect_tunnel_uses_admitted_route(self) -> None:
        self._conn.recv.return_value = _connect_request(b'tunnel.example', 443)
        self._run_once()

        assert FakeServerConnection.connects == [('tunnel.example', 443)]
        assert RoutePolicyPlugin.decisions == [(b'tunnel.example', 443)]
        assert self.protocol_handler.work.buffer[0].tobytes() == \
            PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT

    def test_connect_tunnel_denied_before_connection(self) -> None:
        RoutePolicyPlugin.denied = [(b'tunnel.example', 443)]
        self._conn.recv.return_value = _connect_request(b'tunnel.example', 443)
        self._run_once()

        assert FakeServerConnection.connects == []
        self.mock_server_conn.assert_not_called()
        response = self.protocol_handler.work.buffer[0].tobytes()
        assert response.startswith(b'HTTP/1.1 403')

    @pytest.mark.parametrize(   # type: ignore[misc]
        'order', ('policy_first', 'rewriter_first'),
    )
    def test_rewrite_before_connect_is_re_admitted(
            self, order: str,
    ) -> None:
        # Reverse plugin registration to prove ordering cannot bypass policy.
        if order == 'rewriter_first':
            self.flags.plugins[b'HttpProxyBasePlugin'] = [
                RouteRewriterPlugin, RoutePolicyPlugin, ShortCircuitPlugin,
            ]
            self.protocol_handler = HttpProtocolHandler(
                HttpClientConnection(self._conn, self._addr),
                flags=self.flags,
            )
            self.protocol_handler.initialize()

        RouteRewriterPlugin.hook = 'before_upstream_connection'
        RouteRewriterPlugin.rewrite_to = (b'rewritten.example', 9090)
        self._conn.recv.return_value = _http_request(b'original.example', 8080)
        self._run_once()

        assert FakeServerConnection.connects == [('rewritten.example', 9090)]
        assert (b'rewritten.example', 9090) in RoutePolicyPlugin.decisions
        assert (b'original.example', 8080) not in RoutePolicyPlugin.decisions or \
            RoutePolicyPlugin.decisions[-1] == (b'rewritten.example', 9090)

    def test_rewrite_to_denied_destination_is_rejected(self) -> None:
        RouteRewriterPlugin.hook = 'before_upstream_connection'
        RouteRewriterPlugin.rewrite_to = (b'denied.example', 8080)
        RoutePolicyPlugin.denied = [(b'denied.example', 8080)]
        self._conn.recv.return_value = _http_request(b'allowed.example', 8080)
        self._run_once()

        assert FakeServerConnection.connects == []
        self.mock_server_conn.assert_not_called()
        assert RoutePolicyPlugin.decisions[-1] == (b'denied.example', 8080)
        response = self.protocol_handler.work.buffer[0].tobytes()
        assert response.startswith(b'HTTP/1.1 403')

    def test_rewrite_in_handle_client_request_is_re_admitted(self) -> None:
        RouteRewriterPlugin.hook = 'handle_client_request'
        RouteRewriterPlugin.rewrite_to = (b'rewritten.example', 9090)
        self._conn.recv.return_value = _http_request(b'original.example', 8080)
        self._run_once()

        assert FakeServerConnection.connects == [('rewritten.example', 9090)]
        assert RoutePolicyPlugin.decisions[-1] == (b'rewritten.example', 9090)

    def test_short_circuit_path_is_still_authorized(self) -> None:
        ShortCircuitPlugin.short_circuit = True
        self._conn.recv.return_value = _http_request(b'cached.example', 8080)
        self._run_once()

        assert FakeServerConnection.connects == []
        self.mock_server_conn.assert_not_called()
        assert RoutePolicyPlugin.decisions == [(b'cached.example', 8080)]
        response = HttpParser(httpParserTypes.RESPONSE_PARSER)
        response.parse(self.protocol_handler.work.buffer[0])
        assert response.body == b'cached'

    def test_short_circuit_denied_does_not_serve_cached_response(self) -> None:
        ShortCircuitPlugin.short_circuit = True
        RoutePolicyPlugin.denied = [(b'cached.example', 8080)]
        self._conn.recv.return_value = _http_request(b'cached.example', 8080)
        self._run_once()

        assert FakeServerConnection.connects == []
        response = self.protocol_handler.work.buffer[0].tobytes()
        assert response.startswith(b'HTTP/1.1 403')
        assert b'cached' not in response

    def test_route_authorization_rejected_is_http_protocol_exception(self) -> None:
        exception = RouteAuthorizationRejected(host=b'evil.example', port=443)
        assert isinstance(exception, HttpRequestRejected)
        assert exception.status_code == httpStatusCodes.FORBIDDEN
        packet = exception.response(None)
        assert packet is not None
        assert packet.tobytes().startswith(b'HTTP/1.1 403')

    def test_default_authorize_route_allows(self) -> None:
        class _NoPolicy(HttpProxyBasePlugin):
            pass

        plugin = _NoPolicy.__new__(_NoPolicy)
        request = mock.MagicMock()
        assert plugin.authorize_route(request) is True

    def _new_proxy_plugin(self, request: HttpParser) -> Any:
        return HttpProxyPlugin(
            'test-uid',
            self.flags,
            HttpClientConnection(self._conn, self._addr),
            request,
        )

    def test_admission_helpers_pin_and_compare_routes(self) -> None:
        request = HttpParser(httpParserTypes.REQUEST_PARSER)
        request.parse(memoryview(_http_request(b'pinned.example', 8080)))
        proxy_plugin: Any = self._new_proxy_plugin(request)

        assert proxy_plugin._route(request) == (b'pinned.example', 8080)
        proxy_plugin.authorized_route = (b'pinned.example', 8080)
        # Same destination: no exception.
        proxy_plugin._ensure_route_admitted(request)
        # Different destination without a live connection: re-admitted.
        request.host = b'other.example'
        proxy_plugin._ensure_route_admitted(request)
        assert proxy_plugin.authorized_route == (b'other.example', 8080)

    def test_destination_change_with_live_connection_is_rejected(
            self, mocker: MockerFixture,
    ) -> None:
        request = HttpParser(httpParserTypes.REQUEST_PARSER)
        request.parse(memoryview(_http_request(b'pinned.example', 8080)))
        proxy_plugin: Any = self._new_proxy_plugin(request)
        proxy_plugin.authorized_route = (b'pinned.example', 8080)
        proxy_plugin.upstream = mocker.MagicMock()
        proxy_plugin.upstream.closed = False

        request.host = b'swapped.example'
        with pytest.raises(RouteAuthorizationRejected):
            proxy_plugin._ensure_route_admitted(request)

    def test_origin_form_request_uses_pinned_tunnel_route(self) -> None:
        # TLS-intercepted requests inside a CONNECT tunnel carry only a path.
        connect_request = HttpParser(httpParserTypes.REQUEST_PARSER)
        connect_request.parse(
            memoryview(_connect_request(b'tunnel.example', 443)),
        )
        proxy_plugin: Any = self._new_proxy_plugin(connect_request)
        proxy_plugin.authorized_route = (b'tunnel.example', 443)

        inner_request = HttpParser(httpParserTypes.REQUEST_PARSER)
        inner_request.parse(
            memoryview(
                build_http_request(
                    b'GET', b'/',
                    headers={b'Host': b'tunnel.example'},
                    no_ua=True,
                ),
            ),
        )
        assert inner_request.host is None
        # Admission falls back to the already admitted tunnel destination.
        assert proxy_plugin._pinned_route(inner_request) == (
            b'tunnel.example', 443,
        )
        proxy_plugin._ensure_route_admitted(
            inner_request, (b'tunnel.example', 443),
        )

    def test_pipelined_request_to_other_destination_is_rejected(
            self, mocker: MockerFixture,
    ) -> None:
        request = HttpParser(httpParserTypes.REQUEST_PARSER)
        request.parse(memoryview(_http_request(b'pinned.example', 8080)))
        proxy_plugin: Any = self._new_proxy_plugin(request)
        proxy_plugin.authorized_route = (b'pinned.example', 8080)
        proxy_plugin.upstream = mocker.MagicMock()
        proxy_plugin.upstream.closed = False

        pipelined = HttpParser(httpParserTypes.REQUEST_PARSER)
        pipelined.parse(memoryview(_http_request(b'other.example', 9090)))
        with pytest.raises(RouteAuthorizationRejected):
            proxy_plugin._ensure_route_admitted(
                pipelined, (b'other.example', 9090),
            )
