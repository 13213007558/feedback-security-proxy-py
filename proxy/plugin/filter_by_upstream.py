# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Optional

from ..http import httpStatusCodes
from ..http.proxy import HttpProxyBasePlugin
from ..common.flag import flags
from ..http.parser import HttpParser
from ..common.utils import text_
from ..http.exception import HttpRequestRejected


flags.add_argument(
    '--filtered-upstream-hosts',
    type=str,
    default='facebook.com,www.facebook.com',
    help='Default: Blocks Facebook.  Comma separated list of IPv4 and IPv6 addresses.',
)


class FilterByUpstreamHostPlugin(HttpProxyBasePlugin):
    """Drop traffic by inspecting upstream host."""

    def _is_filtered(self, request: HttpParser) -> bool:
        return text_(request.host) in self.flags.filtered_upstream_hosts.split(',')

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        # Kept for backward compatibility.  The authoritative check lives in
        # authorize_route so it is evaluated against the final, actually
        # connected destination regardless of plugin ordering.
        if self._is_filtered(request):
            raise HttpRequestRejected(
                status_code=httpStatusCodes.I_AM_A_TEAPOT,
                reason=b'I\'m a tea pot',
            )
        return request

    def authorize_route(
            self, request: HttpParser,
    ) -> Optional[bool]:
        if self._is_filtered(request):
            raise HttpRequestRejected(
                status_code=httpStatusCodes.I_AM_A_TEAPOT,
                reason=b'I\'m a tea pot',
            )
        return True
