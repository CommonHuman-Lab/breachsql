# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — engine/_scanner/active/
Error-based, boolean-based, and union-based SQLi detection.

Sub-modules:
  - _helpers : HTTP fetch helper and response comparison utilities

All detection logic (scan_param, _test_error_based, _test_boolean, _test_union,
_detect_db_error, _find_column_count) lives here in __init__.py so that
references can be patched by tests via the package namespace.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from ...log import get_logger
from ...reporter import ErrorBasedFinding, BooleanFinding, UnionFinding, ExtractionFinding, ScanResult
from ...http.injector import Injector
from ...http.waf_detect import EVASION_NONE
from ..options import ScanOptions
from ..payloads import (
    DB_ERROR_PATTERNS,
    apply_evasion,
    get_error_payloads,
    get_boolean_pairs,
    get_db_contents_payloads,
    get_enum_payloads,
    make_marker,
    order_by_probes,
    union_null_probes,
)
from ._helpers import (
    _fetch,
    _diff_score,
    _len_ratio,
    _has_stable_boolean_signal,
    _extract_marker,
    _is_path_reflected,
    _BOOL_CONFIRM_THRESHOLD,
    _BOOL_LIKELY_THRESHOLD,
    _BOOL_LEN_RATIO_THRESHOLD,
)

logger = get_logger("breachsql.active")


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
    url       = surface["url"]
    method    = surface["method"]
    params    = surface["params"]
    param     = surface["single_param"]
    json_body  = surface.get("json_body", False)
    path_index = surface.get("path_index", 0)
    second_url = getattr(opts, "second_url", "")

    # Fetch a clean baseline using the original param value (not empty string),
    # so the baseline represents normal application behaviour for a valid input.
    baseline = _fetch(injector, url, method, params, param, None,
                      second_url=second_url, json_body=json_body, path_index=path_index)
    if baseline is None:
        return

    _prev_error_count   = len(result.error_based)
    _prev_boolean_count = len(result.boolean_based)
    _prev_union_count   = len(result.union_based)

    for evasion in (evasions if evasions else [EVASION_NONE]):
        if opts.use_error and len(result.error_based) == _prev_error_count:
            _test_error_based(url, method, params, param, evasion, opts, injector, result,
                              second_url, json_body, path_index)

        if opts.use_boolean and len(result.boolean_based) == _prev_boolean_count:
            _test_boolean(url, method, params, param, baseline, evasion, opts, injector, result,
                          second_url, json_body, path_index)

        if opts.use_union and opts.level >= 2 and len(result.union_based) == _prev_union_count:
            _test_union(url, method, params, param, evasion, opts, injector, result,
                        second_url, json_body, path_index)

        # Stop escalating if all enabled techniques found something
        _error_done   = (not opts.use_error)  or len(result.error_based)   > _prev_error_count
        _boolean_done = (not opts.use_boolean) or len(result.boolean_based) > _prev_boolean_count
        _union_done   = (not opts.use_union or opts.level < 2) or len(result.union_based) > _prev_union_count
        if _error_done and _boolean_done and _union_done:
            break

    # Level 3: run extended payload sets (db_contents + enum) via error channel
    if opts.level >= 3 and opts.use_error:
        evasion = evasions[0] if evasions else EVASION_NONE
        _dbms = result.dbms_detected or opts.dbms
        _extended = (
            get_db_contents_payloads(_dbms, "tables")
            + get_db_contents_payloads(_dbms, "columns")
            + get_enum_payloads("version")
            + get_enum_payloads("current_user")
            + get_enum_payloads("current_database")
        )
        for raw_payload in _extended:
            payload = apply_evasion(raw_payload, evasion)
            resp = _fetch(injector, url, method, params, param, payload,
                          second_url=second_url, json_body=json_body, path_index=path_index)
            if resp is None:
                continue
            dbms_hit, evidence = _detect_db_error(resp)
            if dbms_hit:
                result.append_error_based(ErrorBasedFinding(
                    url=url, parameter=param, method=method,
                    payload=payload, dbms=dbms_hit, evidence=evidence,
                ))


# ---------------------------------------------------------------------------
# Error-based detection
# ---------------------------------------------------------------------------

def _detect_db_error(body: str) -> Tuple[str, str]:
    """
    Scan *body* for DB error patterns.
    Returns (dbms_name, evidence_snippet) or ("", "").
    """
    body_lower = body.lower()
    # Check specific DBMSes first, then generic
    for dbms in ("mysql", "mariadb", "mssql", "postgres", "sqlite", "oracle", "generic"):
        for pattern in DB_ERROR_PATTERNS[dbms]:
            m = re.search(pattern, body_lower)
            if m:
                start = max(0, m.start() - 30)
                end   = min(len(body), m.end() + 80)
                return dbms, body[start:end].strip()
    return "", ""


def _test_error_based(
    url: str, method: str, params: Dict[str, str], param: str,
    evasion: str, opts: ScanOptions, injector: Injector, result: ScanResult,
    second_url: str = "", json_body: bool = False, path_index: int = 0,
) -> None:
    payloads = get_error_payloads(opts.dbms, opts.risk)

    for raw_payload in payloads:
        payload = apply_evasion(raw_payload, evasion)
        resp = _fetch(injector, url, method, params, param, payload,
                      second_url=second_url, json_body=json_body, path_index=path_index)
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
    second_url: str = "", json_body: bool = False, path_index: int = 0,
) -> None:
    pairs = get_boolean_pairs(opts.risk)

    for raw_true, raw_false in pairs:
        pt = apply_evasion(raw_true,  evasion)
        pf = apply_evasion(raw_false, evasion)

        resp_true  = _fetch(injector, url, method, params, param, pt,
                            second_url=second_url, json_body=json_body, path_index=path_index)
        resp_false = _fetch(injector, url, method, params, param, pf,
                            second_url=second_url, json_body=json_body, path_index=path_index)
        if resp_true is None or resp_false is None:
            continue

        score = _diff_score(resp_true, resp_false)
        baseline_score = _diff_score(baseline, resp_true)

        # Also check content-length divergence — catches tiny textual diffs
        len_ratio = _len_ratio(resp_true, resp_false)
        baseline_len_ratio = _len_ratio(baseline, resp_true)

        # Stable-baseline boolean signal: true response matches baseline
        # while false response diverges — catches single-line blind SQLi
        has_stable_signal = _has_stable_boolean_signal(baseline, resp_true, resp_false)

        stable_baseline = baseline_score <= _BOOL_LIKELY_THRESHOLD and baseline_len_ratio <= _BOOL_LEN_RATIO_THRESHOLD

        is_likely    = (score >= _BOOL_LIKELY_THRESHOLD
                        or (stable_baseline and len_ratio >= _BOOL_LEN_RATIO_THRESHOLD)
                        or has_stable_signal)
        is_confirmed = (score >= _BOOL_CONFIRM_THRESHOLD
                        or (stable_baseline and len_ratio >= _BOOL_LEN_RATIO_THRESHOLD * 2)
                        or has_stable_signal)

        # Ignore if true response is also different from baseline (unstable target)
        if not stable_baseline and not has_stable_signal and not is_likely:
            continue

        if is_likely:
            confirmed = is_confirmed
            logger.finding(
                "Boolean SQLi: %s param=%s score=%.2f len_ratio=%.4f confirmed=%s",
                url, param, score, len_ratio, confirmed,
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
            # Level 3: attempt data extraction via binary-search char extractor
            if opts.level >= 3 and confirmed:
                from ..extract import extract_value, get_extraction_targets
                _dbms = getattr(opts, "dbms", "auto")
                _surface = {"url": url, "method": method, "params": params,
                             "single_param": param,
                             "json_body": json_body, "path_index": path_index}
                for _label, _expr in get_extraction_targets(_dbms):
                    _extracted = extract_value(
                        expr=_expr,
                        surface=_surface,
                        evasions=[evasion],
                        opts=opts,
                        injector=injector,
                        baseline=baseline,
                        mode="boolean",
                    )
                    if _extracted:
                        logger.finding("Extracted via boolean blind: %s param=%s %s=%s",
                                       url, param, _label, _extracted)
                        result.append_extraction(ExtractionFinding(
                            url=url, parameter=param, method=method,
                            expr=_expr, value=_extracted, mode="boolean",
                        ))
            return  # one finding per param


# ---------------------------------------------------------------------------
# Union-based detection
# ---------------------------------------------------------------------------

def _test_union(
    url: str, method: str, params: Dict[str, str], param: str,
    evasion: str, opts: ScanOptions, injector: Injector, result: ScanResult,
    second_url: str = "", json_body: bool = False, path_index: int = 0,
) -> None:
    # Step 1: find column count via ORDER BY
    max_cols = getattr(opts, "max_union_cols", 20)
    col_count = _find_column_count(url, method, params, param, evasion, injector,
                                   second_url, max_cols, json_body, path_index)
    if col_count is None:
        return

    # Step 2: find a reflected column
    marker = make_marker()
    probes = union_null_probes(col_count, marker)

    for raw_payload in probes:
        payload = apply_evasion(raw_payload, evasion)
        resp = _fetch(injector, url, method, params, param, payload,
                      second_url=second_url, json_body=json_body, path_index=path_index)
        if resp is None:
            continue

        if marker in resp:
            # Guard 1: DB error reflection
            err_dbms, _ = _detect_db_error(resp)
            if err_dbms:
                logger.debug(
                    "Union probe: marker found but response also has DB error — "
                    "likely error-reflected payload, skipping param=%s payload=%s",
                    param, payload,
                )
                continue
            # Guard 2: URL/path reflection
            if _is_path_reflected(resp, marker, payload):
                logger.debug(
                    "Union probe: marker found but appears to be URL/path reflection, "
                    "skipping param=%s payload=%s",
                    param, payload,
                )
                continue
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
    evasion: str, injector: Injector, second_url: str = "",
    max_cols: int = 20, json_body: bool = False, path_index: int = 0,
) -> Optional[int]:
    """Determine column count using ORDER BY N probes.

    Probes are generated in pairs (two comment styles per N).  We track the
    last N that did NOT produce a DB error or empty/changed response.  As soon
    as a probe causes the page to lose its normal content (error OR blank
    result), we know N exceeds the real column count.

    DVWA-style apps return an empty body (no data rows) rather than a DB error
    when ORDER BY N exceeds the column count, so we detect both cases.
    """
    import re as _re
    probes = order_by_probes(max_cols=max_cols)
    last_ok: Optional[int] = None

    # Fetch a 'known-good' baseline to detect content disappearance
    baseline_resp = _fetch(injector, url, method, params, param, None,
                           second_url=second_url, json_body=json_body, path_index=path_index)
    baseline_words: set = set()
    if baseline_resp:
        baseline_words = set(w for w in baseline_resp.split() if len(w) > 4)

    # Per-prefix first-seen response — used as reference when the payload changes
    # the injection context
    prefix_baseline: Dict[str, str] = {}

    def _get_prefix(payload: str) -> str:
        m2 = _re.match(r"^(['\"]?\)*)", payload)
        return m2.group(1) if m2 else ""

    def _response_looks_good(resp: str, prefix: str) -> bool:
        pb = prefix_baseline.get(prefix)
        if pb is None:
            return True
        ref_words = set(w for w in pb.split() if len(w) > 4)
        if not ref_words:
            return True
        resp_words = set(w for w in resp.split() if len(w) > 4)
        overlap = len(ref_words & resp_words) / max(len(ref_words), 1)
        return overlap >= 0.80

    seen_n: set = set()
    prefix_last_ok: Dict[str, int] = {}
    prefix_overflow: set = set()

    for raw_payload in probes:
        m = _re.search(r"ORDER BY (\d+)", raw_payload, _re.IGNORECASE)
        if not m:
            continue
        n = int(m.group(1))
        prefix = _get_prefix(raw_payload)

        if prefix in prefix_overflow:
            continue

        payload = apply_evasion(raw_payload, evasion)
        resp = _fetch(injector, url, method, params, param, payload,
                      second_url=second_url, json_body=json_body, path_index=path_index)
        if resp is None:
            continue

        _, err_evidence = _detect_db_error(resp)
        looks_ok = not err_evidence and _response_looks_good(resp, prefix)

        if looks_ok:
            if prefix not in prefix_baseline:
                prefix_baseline[prefix] = resp
            prefix_last_ok[prefix] = n
            last_ok = max(last_ok or 0, n) or None
            seen_n.add(n)
        else:
            p_last = prefix_last_ok.get(prefix)
            if p_last is not None and n > p_last:
                prefix_overflow.add(prefix)

    if prefix_overflow:
        best = max(
            (prefix_last_ok[p] for p in prefix_overflow if p in prefix_last_ok),
            default=None,
        )
        if best is not None:
            return best

    return last_ok


__all__ = [
    "scan_param",
    # helpers
    "_fetch",
    "_diff_score",
    "_len_ratio",
    "_has_stable_boolean_signal",
    "_extract_marker",
    "_is_path_reflected",
    # detection
    "_detect_db_error",
    "_test_error_based",
    "_test_boolean",
    "_test_union",
    "_find_column_count",
    # re-exported from payloads (for backward compat / patching)
    "make_marker",
]
