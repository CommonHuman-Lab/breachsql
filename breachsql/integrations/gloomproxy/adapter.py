# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Translate a GloomProxy ScanContext into BreachSQL ScanOptions."""
from __future__ import annotations

from gloomproxy_sdk import ScanContext
from gloomproxy_sdk.auth import extract_auth

from breachsql.engine._scanner.options import ScanOptions


def build_options(ctx: ScanContext) -> ScanOptions:
    """Build BreachSQL ScanOptions from a GloomProxy ScanContext."""
    cfg = ctx.config
    auth = extract_auth(cfg)

    base_headers: dict[str, str] = dict(cfg.get("headers", {}))
    merged_headers = auth.merged_headers(base_headers)

    cookie_str = cfg.get("cookies", "")
    if not cookie_str and auth.cookies:
        cookie_str = auth.cookie_header

    proxy = cfg.get("proxy", "")

    return ScanOptions(
        crawl=bool(cfg.get("crawl", False)),
        headers=merged_headers or None,
        cookies=cookie_str,
        proxy=proxy,
        timeout=int(cfg.get("timeout", 30)),
        delay=float(cfg.get("delay", 0.0)),
        threads=int(cfg.get("threads", 5)),
        level=int(cfg.get("level", 1)),
        risk=int(cfg.get("risk", 1)),
        technique=str(cfg.get("technique", "EBTUO")),
        dbms=str(cfg.get("dbms", "auto")),
        max_pages=int(cfg.get("max_pages", 50)),
        max_depth=int(cfg.get("max_depth", 3)),
        time_threshold=int(cfg.get("time_threshold", 4)),
        oob_callback=str(cfg.get("oob_callback", "")),
        # Never write output files in distributed mode
        output="",
    )
