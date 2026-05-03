# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — engine/_scanner/passive.py
Fetch the seed page and run passive header/config checks.
"""

from __future__ import annotations

from typing import Optional

import requests

from ..log import get_logger
from ..http.injector import Injector
from ..reporter import ScanResult

logger = get_logger("breachsql.passive")


def fetch_seed(injector: Injector, url: str) -> Optional[requests.Response]:
    """Fetch the target URL once for passive checks and DOM source."""
    try:
        resp = injector.get(url)
        logger.debug("Seed fetch %s → %d (%d bytes)", url, resp.status_code, len(resp.text))
        return resp
    except Exception as exc:
        logger.warning("Seed fetch failed for %s: %s", url, exc)
        return None


def run_passive_checks(
    url: str,
    seed_resp: Optional[requests.Response],
    injector: Injector,
    result: ScanResult,
) -> None:
    """
    Lightweight passive checks relevant to SQLi context.
    Currently checks for verbose error disclosure in the default response
    and notes interesting headers (X-Powered-By, Server) for DBMS hints.
    """
    if seed_resp is None:
        return

    _check_error_disclosure(url, seed_resp, result)
    _check_interesting_headers(url, seed_resp, result)


def _check_error_disclosure(url: str, resp, result: ScanResult) -> None:
    """Log a warning if the default response already contains a DB error."""
    from .active import _detect_db_error  # avoid circular import at module level
    dbms, evidence = _detect_db_error(resp.text)
    if dbms:
        msg = f"Passive: DB error visible in default response [{dbms}] — {evidence[:80]}"
        logger.warning(msg)
        result.append_log(msg)


def _check_interesting_headers(url: str, resp, result: ScanResult) -> None:
    """Log headers that hint at the backend technology / DBMS."""
    interesting = {
        "x-powered-by": "tech hint",
        "server":        "server hint",
        "x-aspnet-version": "ASP.NET — likely MSSQL",
        "x-aspnetmvc-version": "ASP.NET MVC — likely MSSQL",
    }
    for hdr, note in interesting.items():
        val = resp.headers.get(hdr, "")
        if val:
            msg = f"Passive header [{hdr}: {val}] ({note})"
            logger.debug(msg)
            result.append_log(msg)
            # Auto-hint DBMS — only set when the header gives a strong signal
            if result.dbms_detected is None:
                val_lower = val.lower()
                if "mysql" in val_lower or "mariadb" in val_lower:
                    result.dbms_detected = "mysql"
                elif "asp" in val_lower or "iis" in val_lower or "mssql" in val_lower:
                    result.dbms_detected = "mssql"
                elif "postgres" in val_lower or "pgsql" in val_lower:
                    result.dbms_detected = "postgres"
