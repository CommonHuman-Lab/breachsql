# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — engine/scanner.py
Top-level scan() entry point.
"""

from __future__ import annotations

import json

from .log import ScanResultHandler, get_logger
from .http.injector import Injector
from .reporter import ScanResult
from .http import waf_detect  # noqa: F401 (patch target for tests)
from ._scanner.options import ScanOptions  # noqa: F401 (re-exported)
from ._scanner.pipeline import run

logger = get_logger("breachsql.scanner")


def scan(url: str, options: ScanOptions | None = None) -> ScanResult:
    """Run a full BreachSQL scan against *url* and return a ScanResult."""
    if options is None:
        options = ScanOptions()

    result   = ScanResult(target=url)
    _root    = get_logger("breachsql")
    _handler = ScanResultHandler(result)
    _handler.setFormatter(__import__("logging").Formatter("%(name)s: %(message)s"))
    _root.addHandler(_handler)

    injector = Injector(
        timeout=options.timeout,
        proxy=options.proxy or None,
        headers=options.headers or None,
        cookies=options.cookies or None,
        delay=options.delay,
    )

    try:
        run(url, options, injector, result)
    except Exception as exc:
        result.append_error(f"Scan aborted: {exc}")
        logger.exception("BreachSQL scan error")
    finally:
        _root.removeHandler(_handler)
        injector.close()
        result.requests_sent = injector.request_count
        result.finish()

    if options.output:
        try:
            with open(options.output, "w", encoding="utf-8") as fh:
                json.dump(result.to_dict(), fh, indent=2)
        except OSError as exc:
            result.append_error(f"Failed to write output file: {exc}")

    return result
