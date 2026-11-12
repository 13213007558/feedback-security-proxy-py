# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import argparse
from abc import ABC
from typing import TYPE_CHECKING, Any, Dict, Tuple, Optional

from ..parser import HttpParser
from ..connection import HttpClientConnection
from ...core.event import EventQueue
from ..descriptors import DescriptorsHandlerMixin
from ...common.utils import tls_interception_enabled


if TYPE_CHECKING:   # pragma: no cover
    from ...common.types import HostPort
    from ...core.connection import UpstreamConnectionPool


class HttpProxyBasePlugin(
        DescriptorsHandlerMixin,
        ABC,
):
    """Base HttpProxyPlugin Plugin class.

    Implement various lifecycle event methods to customize behavior."""

    def __init__(
            self,
            uid: str,
            flags: argparse.Namespace,
            client: HttpClientConnection,
            event_queue: EventQueue,
            upstream_conn_pool: Optional['UpstreamConnectionPool'] = None,
    ) -> None:
        self.uid = uid                  # pragma: no cover
        self.flags = flags              # pragma: no cover
        self.client = client            # pragma: no cover
        self.event_queue = event_queue  # pragma: no cover
        self.upstream_conn_pool = upstream_conn_pool

    def name(self) -> str:
        """A unique name for your plugin.

        Defaults to name of the class. This helps plugin developers to directly
        access a specific plugin by its name."""
        return self.__class__.__qualname__      # pragma: no cover

    def resolve_dns(self, host: str, port: int) -> Tuple[Optional[str], Optional['HostPort']]:
        """Resolve upstream server host to an IP address.

        Optionally also override the source address to use for
        connection with upstream server.

        For upstream IP:
        Return None to use default resolver available to the system.
        Return IP address as string to use your custom resolver.

        For source address:
        Return None to use default source address
        Return 2-tuple representing (host, port) to use as source address
        """
        return None, None

    # No longer abstract since 2.4.0
    #
    # @abstractmethod
    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        """Handler called just before Proxy upstream connection is established.

        Return optionally modified request object.
        If None is returned, upstream connection won't be established.

        Raise HttpRequestRejected or HttpProtocolException directly to drop the connection.

        Routing security contract:

        - This hook runs *before* any upstream socket is opened.  Rejecting
          here therefore never establishes a connection.
        - Plugins MAY rewrite the request destination (``request.host`` /
          ``request.port``, e.g. via ``request.set_url``) from this hook.  The
          core re-runs :meth:`authorize_route` afterwards, so the rewritten
          destination is admitted before a connection is made.
        - Do NOT rely on this hook alone for destination based access control.
          A later plugin can still rewrite the destination, so authorization
          policies must be implemented in :meth:`authorize_route`, which is
          always evaluated against the final, actually connected host:port.
        """
        return request  # pragma: no cover

    # Since 3.4.0
    #
    # @abstractmethod
    def authorize_route(
            self, request: HttpParser,
    ) -> Optional[bool]:
        """Final route admission hook.

        Called by the core after all :meth:`before_upstream_connection` and
        :meth:`handle_client_request` plugins have run, immediately before the
        request is dispatched on its upstream connection.  It is invoked for
        both plain HTTP proxy requests and ``CONNECT`` (HTTPS tunnel) requests,
        and again for every pipelined request on an already established
        upstream connection.

        ``request.host`` and ``request.port`` at this point describe the exact
        destination the proxy will connect (or has connected) to.  Implement
        destination based allow/deny policies here instead of in
        :meth:`before_upstream_connection`, so authorization can never be
        bypassed by plugin ordering or by another plugin rewriting the route.

        Return:

        - ``True`` (default) to admit the route.
        - ``False`` or raise :class:`~proxy.http.exception.HttpRequestRejected`
          (or :class:`~proxy.http.exception.RouteAuthorizationRejected`) to
          reject it.  No upstream connection is established when a rejection
          happens before connect.

        The core invokes every plugin's ``authorize_route`` and rejects the
        request if any single plugin rejects it.  If a plugin changes the
        destination after admission, the core re-runs this hook against the new
        destination; when the destination of an already established connection
        is changed, the request is instead rejected outright because the open
        connection cannot be repurposed for a different host:port.
        """
        return True  # pragma: no cover

    # Since 3.4.0
    #
    # @abstractmethod
    def handle_client_data(
            self, raw: memoryview,
    ) -> Optional[memoryview]:
        """Handler called in special scenarios when an upstream server connection
        is never established.

        Essentially, if you return None from within before_upstream_connection,
        be prepared to handle_client_data and not handle_client_request.

        Only called after initial request from client has been received.

        Raise HttpRequestRejected to tear down the connection
        Return None to drop the connection

        Short-circuit contract: when a plugin takes over the request without an
        upstream connection (returns None from
        :meth:`before_upstream_connection`), it owns the full client exchange.
        Route admission is still performed before this hook is used, hence any
        response queued directly to the client here has already been authorized
        against the requested destination.  Such a plugin MUST NOT open its own
        network connection to a destination that
        :meth:`authorize_route` would not admit.
        """
        return raw  # pragma: no cover

    # No longer abstract since 2.4.0
    #
    # @abstractmethod
    def handle_client_request(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        """Handler called before dispatching client request to upstream.

        Note: For pipelined (keep-alive) connections, this handler can be
        called multiple times, for each request sent to upstream.

        Note: If TLS interception is enabled, this handler can
        be called multiple times if client exchanges multiple
        requests over same SSL session.

        Return optionally modified request object to dispatch to upstream.
        Return None to drop the request data, e.g. in case a response has already been queued.
        Raise HttpRequestRejected or HttpProtocolException directly to
        tear down the connection with client.

        Routing security contract:

        - On the first request this hook runs AFTER the final
          :meth:`authorize_route` admission but BEFORE the upstream connection
          is established.  Rewriting ``request.host`` / ``request.port`` here
          invalidates the prior admission; the core re-runs
          :meth:`authorize_route` for the new destination and only connects if
          it is admitted.
        - On pipelined requests the upstream connection already exists and is
          pinned to a specific host:port.  Changing the destination here (or in
          any later hook) is rejected with
          :class:`~proxy.http.exception.RouteAuthorizationRejected` instead of
          sending traffic for a different destination over the admitted
          connection.
        - Returning None is the supported short-circuit (e.g. cache hit): no
          request reaches the upstream and no further routing checks are needed
          because admission already succeeded for this destination.
        """
        return request  # pragma: no cover

    # No longer abstract since 2.4.0
    #
    # @abstractmethod
    def handle_upstream_chunk(self, chunk: memoryview) -> Optional[memoryview]:
        """Handler called right after receiving raw response from upstream server.

        For HTTPS connections, chunk will be encrypted unless
        TLS interception is also enabled.

        Return None if you don't want to sent this chunk to the client.
        """
        return chunk  # pragma: no cover

    # No longer abstract since 2.4.0
    #
    # @abstractmethod
    def on_upstream_connection_close(self) -> None:
        """Handler called right after upstream connection has been closed."""
        pass  # pragma: no cover

    def on_access_log(self, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Use this method to override default access log format (see
        DEFAULT_HTTP_ACCESS_LOG_FORMAT and DEFAULT_HTTPS_ACCESS_LOG_FORMAT) and to
        add/update/modify/delete context for next plugin.on_access_log invocation.

        This is specially useful if a plugins want to provide extra context
        in the access log which may not available within other plugins' context or even
        in proxy.py core.

        Returns Log context or None.  If plugin chooses to access log, they ideally
        must return None to prevent other plugin.on_access_log invocation.
        """
        return context

    def do_intercept(self, _request: HttpParser) -> bool:
        """By default returns True (only) when necessary flags
        for TLS interception are passed.

        When TLS interception is enabled, plugins can still disable
        TLS interception by returning False explicitly.  This hook
        will allow you to run proxy instance with TLS interception
        flags BUT only conditionally enable interception for
        certain requests.
        """
        return tls_interception_enabled(self.flags)
