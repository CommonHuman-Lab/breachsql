# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""BreachSQL — engine/http/injector.py"""

from commonhuman_core.http import HttpClient, AsyncHttpClient, parse_cookie_string, parse_post_data

# Synchronous alias (legacy / test compatibility)
Injector = HttpClient

# Async alias — used by the scan engine post-migration
AsyncInjector = AsyncHttpClient

__all__ = ["Injector", "AsyncInjector", "HttpClient", "AsyncHttpClient", "parse_cookie_string", "parse_post_data"]
