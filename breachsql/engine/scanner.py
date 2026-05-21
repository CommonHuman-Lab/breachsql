# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — engine/scanner.py
Top-level scan() entry point.
"""

from __future__ import annotations

import json
import os

from .log import ScanResultHandler, get_logger
from .http.injector import Injector
from .reporter import ScanResult
from .http import waf_detect  # noqa: F401 (patch target for tests)
from ._scanner.options import ScanOptions  # noqa: F401 (re-exported)
from ._scanner.pipeline import run

logger = get_logger("breachsql.scanner")


_OUTPUT_EXTS = {".json", ".txt", ".html"}


def _output_stem(path: str) -> str:
    """Strip extension only if it's one of our known output types (not e.g. '.1' in an IP)."""
    root, ext = os.path.splitext(path)
    return root if ext.lower() in _OUTPUT_EXTS else path


def _unique_stem(stem: str) -> str:
    """Return *stem* unchanged if no collision exists, else append _1, _2, …"""
    suffixes = (".json", ".txt", "_dump.json", ".html")
    if not any(os.path.exists(stem + s) for s in suffixes):
        return stem
    counter = 1
    while any(os.path.exists(f"{stem}_{counter}{s}") for s in suffixes):
        counter += 1
    return f"{stem}_{counter}"


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
        stem = _output_stem(options.output)
        try:
            with open(stem + ".json", "w", encoding="utf-8") as fh:
                json.dump(result.to_dict(), fh, indent=2)
        except OSError as exc:
            result.append_error(f"Failed to write JSON output: {exc}")
        try:
            from breachsql._cli.summary import format_summary
            with open(stem + ".txt", "w", encoding="utf-8") as fh:
                fh.write(format_summary(result))
        except OSError as exc:
            result.append_error(f"Failed to write text output: {exc}")

    if options.output and result.table_dumps:
        stem = _output_stem(options.output)
        try:
            with open(stem + "_dump.json", "w", encoding="utf-8") as fh:
                json.dump(result.dumps_to_dict(), fh, indent=2)
        except OSError as exc:
            result.append_error(f"Failed to write dump file: {exc}")

    return result
