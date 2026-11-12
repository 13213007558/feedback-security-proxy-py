# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       route
"""
from typing import Any, Optional

from .http_request_rejected import HttpRequestRejected
from ..codes import httpStatusCodes


class RouteAuthorizationRejected(HttpRequestRejected):
    """Raised when the final routing decision for a request is not authorized.

    Unlike :class:`HttpRequestRejected`, which plugins may raise at any stage of
    request handling, this exception is reserved for the explicit final route
    admission phase.  It guarantees that authorization was evaluated against the
    exact ``host:port`` the proxy is about to (or already did) connect to.

    The core also raises this exception when a plugin rewrites the request
    destination after the final route has been admitted, because the original
    admission decision no longer covers the new destination.
    """

    def __init__(
            self,
            host: Optional[bytes] = None,
            port: Optional[int] = None,
            reason: Optional[bytes] = None,
            **kwargs: Any,
    ) -> None:
        self.host: Optional[bytes] = host
        self.port: Optional[int] = port
        destination = b'%b:%s' % (
            host or b'?',
            b'?' if port is None else str(port).encode(),
        )
        super().__init__(
            status_code=httpStatusCodes.FORBIDDEN,
            reason=reason or b'Route not authorized: ' + destination,
            **kwargs,
        )
