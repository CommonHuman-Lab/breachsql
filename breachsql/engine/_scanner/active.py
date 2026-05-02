# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — engine/_scanner/active.py
Error-based, boolean-based, and union-based SQLi detection.
"""

from __future__ import annotations

import difflib
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from ..log import get_logger
from ..reporter import ErrorBasedFinding, BooleanFinding, UnionFinding, ScanResult
from ..http.injector import Injector, parse_post_data
from ..http.waf_detect import EVASION_NONE
from .options import ScanOptions
from .payloads import (
    DB_ERROR_PATTERNS,
    apply_evasion,
    get_error_payloads,
    get_boolean_pairs,
    make_marker,
    order_by_probes,
    union_null_probes,
)

logger = get_logger("breachsql.active")

# diff score threshold above which we consider a boolean result confirmed
_BOOL_CONFIRM_THRESHOLD = 0.20
# diff score threshold above which we flag it as likely (lower confidence)
_BOOL_LIKELY_THRESHOLD  = 0.10


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def scan_param(
    surface: Dict[str, Any],
    evasions: List[str],
    opts: ScanOptions,
    injector: Injector,
    result: ScanResult,
) -> None:
    """
    Test a single injectable surface for SQLi.
    surface keys: url, method, params, single_param
    """
    url    = surface["url"]
    method = surface["method"]
    params = surface["params"]
    param  = surface["single_param"]

    # Fetch a clean baseline response
    baseline = _fetch(injector, url, method, params, param, "")
    if baseline is None:
        return

    evasion = evasions[0] if evasions else EVASION_NONE

    if opts.use_error:
        _test_error_based(url, method, params, param, evasion, opts, injector, result)

    if opts.use_boolean:
        _test_boolean(url, method, params, param, baseline, evasion, opts, injector, result)

    if opts.use_union and opts.level >= 2:
        _test_union(url, method, params, param, evasion, opts, injector, result)


# ---------------------------------------------------------------------------
# Error-based detection
# ---------------------------------------------------------------------------

def _test_error_based(
    url: str, method: str, params: Dict[str, str], param: str,
    evasion: str, opts: ScanOptions, injector: Injector, result: ScanResult,
) -> None:
    payloads = get_error_payloads(opts.dbms, opts.risk)

    for raw_payload in payloads:
        payload = apply_evasion(raw_payload, evasion)
        resp = _fetch(injector, url, method, params, param, payload)
        if resp is None:
            continue

        dbms, evidence = _detect_db_error(resp)
        if dbms:
            logger.finding(
                "Error-based SQLi: %s param=%s payload=%s dbms=%s",
                url, param, payload, dbms,
            )
            result.append_error_based(ErrorBasedFinding(
                url=url,
                parameter=param,
                method=method,
                payload=payload,
                dbms=dbms,
                evidence=evidence,
            ))
            # Auto-detect DBMS for the rest of the scan
            if result.dbms_detected is None and dbms != "generic":
                result.dbms_detected = dbms
            # One confirmed finding per param is enough
            return


# ---------------------------------------------------------------------------
# Boolean-based detection
# ---------------------------------------------------------------------------

def _test_boolean(
    url: str, method: str, params: Dict[str, str], param: str,
    baseline: str, evasion: str, opts: ScanOptions, injector: Injector, result: ScanResult,
) -> None:
    pairs = get_boolean_pairs(opts.risk)

    for raw_true, raw_false in pairs:
        pt = apply_evasion(raw_true,  evasion)
        pf = apply_evasion(raw_false, evasion)

        resp_true  = _fetch(injector, url, method, params, param, pt)
        resp_false = _fetch(injector, url, method, params, param, pf)
        if resp_true is None or resp_false is None:
            continue

        score = _diff_score(resp_true, resp_false)
        baseline_score = _diff_score(baseline, resp_true)

        # Ignore if true response is also different from baseline (unstable target)
        if baseline_score > _BOOL_LIKELY_THRESHOLD and score < _BOOL_LIKELY_THRESHOLD:
            continue

        if score >= _BOOL_LIKELY_THRESHOLD:
            confirmed = score >= _BOOL_CONFIRM_THRESHOLD
            logger.finding(
                "Boolean SQLi: %s param=%s score=%.2f confirmed=%s",
                url, param, score, confirmed,
            )
            result.append_boolean(BooleanFinding(
                url=url,
                parameter=param,
                method=method,
                payload_true=pt,
                payload_false=pf,
                diff_score=score,
                confirmed=confirmed,
                evidence=resp_true[:200],
            ))
            return  # one finding per param


# ---------------------------------------------------------------------------
# Union-based detection
# ---------------------------------------------------------------------------

def _test_union(
    url: str, method: str, params: Dict[str, str], param: str,
    evasion: str, opts: ScanOptions, injector: Injector, result: ScanResult,
) -> None:
    # Step 1: find column count via ORDER BY
    col_count = _find_column_count(url, method, params, param, evasion, injector)
    if col_count is None:
        return

    # Step 2: find a reflected column
    marker = make_marker()
    probes = union_null_probes(col_count, marker)

    for raw_payload in probes:
        payload = apply_evasion(raw_payload, evasion)
        resp = _fetch(injector, url, method, params, param, payload)
        if resp is None:
            continue

        if marker in resp:
            logger.finding(
                "Union SQLi: %s param=%s cols=%d payload=%s",
                url, param, col_count, payload,
            )
            result.append_union(UnionFinding(
                url=url,
                parameter=param,
                method=method,
                payload=payload,
                column_count=col_count,
                extracted=_extract_marker(resp, marker),
            ))
            return


def _find_column_count(
    url: str, method: str, params: Dict[str, str], param: str,
    evasion: str, injector: Injector,
) -> Optional[int]:
    """Binary-search for column count using ORDER BY N."""
    probes = order_by_probes(max_cols=20)
    last_ok = None

    for raw_payload in probes:
        payload = apply_evasion(raw_payload, evasion)
        resp = _fetch(injector, url, method, params, param, payload)
        if resp is None:
            continue
        # An error response means we exceeded the column count
        _, err_evidence = _detect_db_error(resp)
        if err_evidence:
            return last_ok
        last_ok = int(raw_payload.strip("' ").split()[-1].rstrip("-"))

    return last_ok


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fetch(
    injector: Injector,
    url: str,
    method: str,
    params: Dict[str, str],
    param: str,
    value: str,
) -> Optional[str]:
    """Inject *value* into *param* and return response text, or None on error."""
    injected = {**params, param: value}
    try:
        if method.upper() == "POST":
            resp = injector.post(url, data=injected)
        else:
            resp = injector.inject_get(url, param, value)
        return resp.text
    except Exception as exc:
        logger.debug("Request error for %s param=%s: %s", url, param, exc)
        return None


def _detect_db_error(body: str) -> Tuple[str, str]:
    """
    Scan *body* for DB error patterns.
    Returns (dbms_name, evidence_snippet) or ("", "").
    """
    body_lower = body.lower()
    # Check specific DBMSes first, then generic
    for dbms in ("mysql", "mssql", "postgres", "sqlite", "generic"):
        for pattern in DB_ERROR_PATTERNS[dbms]:
            m = re.search(pattern, body_lower)
            if m:
                start = max(0, m.start() - 30)
                end   = min(len(body), m.end() + 80)
                return dbms, body[start:end].strip()
    return "", ""


def _diff_score(a: str, b: str) -> float:
    """
    Return a similarity *distance* between two response bodies.
    0.0 = identical, 1.0 = completely different.
    """
    ratio = difflib.SequenceMatcher(None, a[:4000], b[:4000]).ratio()
    return 1.0 - ratio


def _extract_marker(body: str, marker: str) -> str:
    """Extract a short snippet around the marker from the response body."""
    idx = body.find(marker)
    if idx == -1:
        return ""
    return body[max(0, idx - 10): idx + len(marker) + 50]
