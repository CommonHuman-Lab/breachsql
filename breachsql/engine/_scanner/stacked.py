# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — engine/_scanner/stacked.py
Stacked (batched) query SQLi detection.

Stacked queries inject a second statement after the primary query using a
semicolon terminator.  Not all databases or application frameworks support
this: Oracle never does, and MySQL only supports it through certain PHP/Python
APIs.  When supported, stacked queries enable powerful post-exploitation
capabilities (WAITFOR DELAY, xp_cmdshell, schema enumeration).

Detection approach:
  1. Inject safe stacked payloads (SELECT 1, SELECT version() etc.).
  2. A confirmed stacked finding requires a response difference from baseline
     (for data-returning payloads) OR a timing signal (for WAITFOR / SLEEP).
  3. For databases that return data, try to extract the stacked result.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..log import get_logger
from ..reporter import StackedFinding, ScanResult
from ..http.injector import Injector
from ..http.waf_detect import EVASION_NONE
from .options import ScanOptions
from .payloads import apply_evasion, get_stacked_payloads
from .active import _fetch, _diff_score, _detect_db_error

logger = get_logger("breachsql.stacked")

# Minimum diff score to consider a stacked query as having caused a response change
_STACKED_DIFF_THRESHOLD = 0.05


def run_stacked(
    surface: Dict[str, Any],
    evasions: List[str],
    opts: ScanOptions,
    injector: Injector,
    result: ScanResult,
) -> None:
    """Test a single surface for stacked (batched) query SQLi."""
    url        = surface["url"]
    method     = surface["method"]
    params     = surface["params"]
    param      = surface["single_param"]
    json_body  = surface.get("json_body", False)
    path_index = surface.get("path_index", 0)
    second_url = getattr(opts, "second_url", "")

    evasion = evasions[0] if evasions else EVASION_NONE
    dbms    = result.dbms_detected or opts.dbms

    payloads = get_stacked_payloads(dbms, opts.risk)
    if not payloads:
        # Oracle (and unknown DBMS with no payloads) — skip
        return

    # Baseline
    baseline = _fetch(injector, url, method, params, param, None,
                      second_url=second_url, json_body=json_body,
                      path_index=path_index)
    if baseline is None:
        return

    for raw_payload in payloads:
        payload = apply_evasion(raw_payload, evasion)
        resp = _fetch(injector, url, method, params, param, payload,
                      second_url=second_url, json_body=json_body,
                      path_index=path_index)
        if resp is None:
            continue

        # Check for DB error first — a stacked syntax error would mean
        # the DB does *not* support stacked queries (or the syntax is wrong).
        err_dbms, _ = _detect_db_error(resp)
        if err_dbms:
            continue

        score = _diff_score(baseline, resp)
        if score >= _STACKED_DIFF_THRESHOLD:
            logger.finding(
                "Stacked query SQLi: %s param=%s score=%.2f payload=%s",
                url, param, score, payload,
            )
            result.append_stacked(StackedFinding(
                url=url,
                parameter=param,
                method=method,
                payload=payload,
                dbms=dbms,
                evidence=resp[:200],
            ))
            if result.dbms_detected is None and dbms not in ("auto", "unknown", ""):
                result.dbms_detected = dbms
            return  # one finding per param
