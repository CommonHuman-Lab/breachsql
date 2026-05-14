# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""BreachSQL — engine/http/injector.py"""

from commonhuman_core.http import HttpClient, parse_cookie_string, parse_post_data

# Alias: Injector IS HttpClient — no subclass needed, all methods already present.
Injector = HttpClient

__all__ = ["Injector", "HttpClient", "parse_cookie_string", "parse_post_data"]
