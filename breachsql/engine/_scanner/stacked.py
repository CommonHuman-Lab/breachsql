# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — engine/_scanner/stacked.py
Stacked (batched) query SQLi detection (async).
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..log import get_logger
from ..reporter import StackedFinding, ScanResult
from ..http.injector import AsyncInjector
from ..http.waf_detect import EVASION_NONE
from .options import ScanOptions
from .payloads import apply_evasion, get_stacked_payloads
from .active import _async_fetch, _diff_score, _detect_db_error
from .blind import _async_timed_fetch

logger = get_logger("breachsql.stacked")

_STACKED_DIFF_THRESHOLD = 0.05


async def run_stacked(
    surface: Dict[str, Any],
    evasions: List[str],
    opts: ScanOptions,
    injector: AsyncInjector,
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

    dbms = result.dbms_detected or opts.dbms

    payloads = get_stacked_payloads(dbms, opts.risk)
    if not payloads:
        return

    baseline = await _async_fetch(injector, url, method, params, param, None,
                                  second_url=second_url, json_body=json_body,
                                  path_index=path_index)
    if baseline is None:
        return

    _prev_count = len(result.stacked)

    for evasion in (evasions if evasions else [EVASION_NONE]):
        for raw_payload in payloads:
            payload = apply_evasion(raw_payload, evasion)

            _is_timing = any(kw in raw_payload.lower() for kw in ("sleep(", "waitfor delay"))

            confirmed = False
            evidence  = ""

            if _is_timing:
                elapsed = await _async_timed_fetch(
                    injector, url, method, params, param, payload,
                    second_url=second_url, json_body=json_body, path_index=path_index,
                )
                if elapsed is None or elapsed < opts.time_threshold:
                    continue
                elapsed2 = await _async_timed_fetch(
                    injector, url, method, params, param, payload,
                    second_url=second_url, json_body=json_body, path_index=path_index,
                )
                if elapsed2 is None or elapsed2 < opts.time_threshold:
                    continue
                confirmed = True
            else:
                resp = await _async_fetch(injector, url, method, params, param, payload,
                                          second_url=second_url, json_body=json_body,
                                          path_index=path_index)
                if resp is None:
                    continue
                err_dbms, _ = _detect_db_error(resp)
                if err_dbms:
                    continue
                score = _diff_score(baseline, resp)
                if score >= _STACKED_DIFF_THRESHOLD:
                    confirmed = True
                    evidence  = resp[:200]

            if confirmed:
                logger.finding(
                    "Stacked query SQLi: %s param=%s payload=%s",
                    url, param, payload,
                )
                result.append_stacked(StackedFinding(
                    url=url,
                    parameter=param,
                    method=method,
                    payload=payload,
                    dbms=dbms,
                    evidence=evidence,
                ))
                if result.dbms_detected is None and dbms not in ("auto", "unknown", ""):
                    result.dbms_detected = dbms
                return

        if len(result.stacked) > _prev_count:
            break
