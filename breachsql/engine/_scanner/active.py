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
# content-length ratio difference that alone signals a boolean response divergence
_BOOL_LEN_RATIO_THRESHOLD = 0.02  # 2% length difference


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

    evasion = evasions[0] if evasions else EVASION_NONE

    if opts.use_error:
        _test_error_based(url, method, params, param, evasion, opts, injector, result,
                          second_url, json_body, path_index)

    if opts.use_boolean:
        _test_boolean(url, method, params, param, baseline, evasion, opts, injector, result,
                      second_url, json_body, path_index)

    if opts.use_union and opts.level >= 2:
        _test_union(url, method, params, param, evasion, opts, injector, result,
                    second_url, json_body, path_index)


# ---------------------------------------------------------------------------
# Error-based detection
# ---------------------------------------------------------------------------

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
        # (e.g. "User ID exists" vs "User ID is MISSING") in large HTML pages
        len_ratio = _len_ratio(resp_true, resp_false)
        baseline_len_ratio = _len_ratio(baseline, resp_true)

        # Stable-baseline boolean signal: true response matches baseline
        # while false response diverges — catches single-line blind SQLi
        has_stable_signal = _has_stable_boolean_signal(baseline, resp_true, resp_false)

        # A strong boolean signal is either a content diff OR a length divergence
        # that does not also appear between baseline and the true response
        # (which would indicate an unstable/dynamic page).
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
            # Guard 1: DB error reflection — the escaped payload in an SQL error.
            err_dbms, _ = _detect_db_error(resp)
            if err_dbms:
                logger.debug(
                    "Union probe: marker found but response also has DB error — "
                    "likely error-reflected payload, skipping param=%s payload=%s",
                    param, payload,
                )
                continue
            # Guard 2: URL/path reflection — some apps echo the full URL or query
            # string in a generic error page (e.g. "Unexpected path: ...MARKER...").
            # In that case the marker is inside the injected value's URL encoding,
            # not extracted by the UNION.  Detect by checking if the marker sits
            # inside a <title> element or adjacent to the literal payload text.
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
        # Use a small set of non-trivial tokens from the baseline as a presence check
        baseline_words = set(w for w in baseline_resp.split() if len(w) > 4)

    # Per-prefix first-seen response — used as reference when the payload changes
    # the injection context (e.g. ')) context returns empty results rather than
    # echoing the baseline content, so the global baseline_words would misclassify
    # a valid ORDER BY N as "bad").
    prefix_baseline: Dict[str, str] = {}

    def _get_prefix(payload: str) -> str:
        """Extract the injection context prefix from a payload."""
        m2 = _re.match(r"^(['\"]?\)*)", payload)
        return m2.group(1) if m2 else ""

    def _response_looks_good(resp: str, prefix: str) -> bool:
        """Return True if the response still contains expected content.

        Uses a per-prefix baseline when available so that contexts that change
        the result set (e.g. ')) that breaks out of a LIKE clause returns empty
        rows) are compared against their own first-seen response rather than the
        uninjected baseline.
        """
        pb = prefix_baseline.get(prefix)
        if pb is None:
            # No baseline yet for this prefix — treat no-error response as valid
            # and record it as the baseline for future comparison.
            return True
        # Compare against the first valid response seen for this prefix
        ref_words = set(w for w in pb.split() if len(w) > 4)
        if not ref_words:
            return True
        resp_words = set(w for w in resp.split() if len(w) > 4)
        overlap = len(ref_words & resp_words) / max(len(ref_words), 1)
        return overlap >= 0.80

    seen_n: set = set()
    # Per-prefix last_ok and confirmed-overflow tracking
    prefix_last_ok: Dict[str, int] = {}
    prefix_overflow: set = set()  # prefixes where we've seen an overflow (N too large)

    for raw_payload in probes:
        m = _re.search(r"ORDER BY (\d+)", raw_payload, _re.IGNORECASE)
        if not m:
            continue
        n = int(m.group(1))
        prefix = _get_prefix(raw_payload)

        # Skip prefixes that have already confirmed their column count
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
            # Record the first good response for this prefix as its baseline
            if prefix not in prefix_baseline:
                prefix_baseline[prefix] = resp
            prefix_last_ok[prefix] = n
            last_ok = max(last_ok or 0, n) or None
            seen_n.add(n)
        else:
            p_last = prefix_last_ok.get(prefix)
            if p_last is not None and n > p_last:
                # This prefix has overflowed — record its column count
                prefix_overflow.add(prefix)

    # Return the column count from the prefix that gave the most columns
    if prefix_overflow:
        # Prefer the confirmed (overflowed) prefix with highest last_ok
        best = max(
            (prefix_last_ok[p] for p in prefix_overflow if p in prefix_last_ok),
            default=None,
        )
        if best is not None:
            return best

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
    value: Optional[str],
    second_url: str = "",
    json_body: bool = False,
    path_index: int = 0,
) -> Optional[str]:
    """
    Inject *value* into *param* and return response text, or None on error.

    If *value* is ``None`` (baseline fetch), the original parameter value is
    used unchanged — this keeps the baseline representative of normal app
    behaviour for a valid input, rather than an empty/missing param which may
    trigger a different code path (redirect, "no results", error page).

    Otherwise the payload is **appended** to the existing parameter value.
    This is essential for correct SQL injection: a payload like
    ``' AND '1'='1`` is meaningless on its own — it needs to be attached to
    the original value (e.g. ``1``) so the full injected string becomes
    ``1' AND '1'='1``.

    If *second_url* is provided, the injection is submitted to *url* (or the
    POST target) but the response is read from *second_url* (GET).  This
    supports two-step injection patterns like DVWA high-security SQLI where
    the payload is submitted to a session-input page and the result is
    rendered on a different page.
    """
    import urllib.parse as _up

    # Resolve original param value (from URL query string for GET, from params dict otherwise)
    if method.upper() == "GET":
        qs = _up.parse_qs(_up.urlparse(url).query, keep_blank_values=True)
        original = qs.get(param, [""])[0]
    else:
        original = params.get(param, "")

    if value is None:
        # Baseline: send the original value unmodified
        injected_value = original
    else:
        # Inject: append payload to the original value
        injected_value = original + value

    injected = {**params, param: injected_value}

    try:
        if second_url:
            # Two-step pattern: inject into url/POST, read result from second_url
            if method.upper() == "POST":
                if json_body:
                    injector.post(url, json_body=injected)
                else:
                    injector.post(url, data=injected)
            elif method.upper() == "PATH":
                injector.inject_path(url, path_index, injected[param])
            else:
                injector.inject_get(url, param, injected[param])
            resp = injector.get(second_url)
        elif method.upper() == "POST":
            if json_body:
                resp = injector.post(url, json_body=injected)
            else:
                resp = injector.post(url, data=injected)
        elif method.upper() == "PATH":
            resp = injector.inject_path(url, path_index, injected[param])
        else:
            # For GET, rebuild the URL with the injected param value
            resp = injector.inject_get(url, param, injected[param])

        # Treat error HTTP status codes as non-injected responses to avoid
        # false positives from WAF block pages (429, 503) or server errors (5xx).
        if hasattr(resp, "status_code") and resp.status_code in (429, 503):
            logger.debug(
                "HTTP %d on %s param=%s — treating as baseline noise",
                resp.status_code, url, param,
            )
            return None

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
    for dbms in ("mysql", "mariadb", "mssql", "postgres", "sqlite", "oracle", "generic"):
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

    Uses multiple signals:
    1. SequenceMatcher over character runs (fast, catches large diffs)
    2. Exclusive-line ratio: lines that appear in exactly one of the two responses.
       This catches single changed lines in an otherwise-identical large HTML page
       (e.g. boolean-blind "User ID exists" vs "User ID is MISSING").

    The maximum of all signals is returned.
    """
    # Character-level ratio over first 4000 chars
    char_ratio = difflib.SequenceMatcher(None, a[:4000], b[:4000]).ratio()
    char_score = 1.0 - char_ratio

    # Exclusive-line score: (|A-B| + |B-A|) / (|A| + |B|)
    a_lines = set(a.splitlines())
    b_lines = set(b.splitlines())
    total_unique = len(a_lines) + len(b_lines)
    if total_unique > 0:
        exclusive = len(a_lines - b_lines) + len(b_lines - a_lines)
        exclusive_score = exclusive / total_unique
    else:
        exclusive_score = 0.0

    return max(char_score, exclusive_score)


def _has_stable_boolean_signal(
    baseline: str,
    resp_true: str,
    resp_false: str,
) -> bool:
    """
    Return True when there is a reliable boolean divergence between
    *resp_true* and *resp_false* that is NOT present between *baseline*
    and *resp_true* (i.e. the true condition matches the baseline behaviour).

    This covers the DVWA-style blind case where the true/false responses
    differ in exactly one content line (e.g. "User ID exists" vs
    "User ID is MISSING") while being otherwise byte-for-byte identical —
    a difference too small for SequenceMatcher-based scoring to detect.
    """
    # Lines exclusively in resp_true but not resp_false (and not empty/whitespace)
    true_lines  = set(l for l in resp_true.splitlines()  if l.strip())
    false_lines = set(l for l in resp_false.splitlines() if l.strip())
    base_lines  = set(l for l in baseline.splitlines()   if l.strip())

    # We need at least one exclusive line on *each* side (true says X, false says Y)
    true_exclusive  = true_lines  - false_lines
    false_exclusive = false_lines - true_lines

    if not true_exclusive or not false_exclusive:
        return False

    # The baseline should be stable relative to *one* of the two sides,
    # confirming this is a data-dependent response (not a random/dynamic page).
    # Case A: baseline looks like the "true" response (normal user exists)
    if true_exclusive & base_lines:
        return True
    # Case B: baseline looks like the "false" response (empty/non-existent value)
    if false_exclusive & base_lines:
        return True
    # Case C: baseline has no unique lines from either side — still confirm
    # if true and false have symmetric exclusive lines (both sides diverge),
    # but guard against dynamic pages (CSRF tokens, timestamps) by requiring:
    # 1. Very few exclusive lines relative to total (CSRF tokens produce many)
    # 2. The exclusive lines must not look like random tokens (length check)
    # 3. The true/false pages must be broadly similar (not just random noise)
    total_lines = max(len(true_lines), len(false_lines), 1)
    if (len(true_exclusive) <= 3 and len(false_exclusive) <= 3
            and len(true_exclusive) / total_lines < 0.10):
        # Additional guard: reject if any exclusive line looks like a random token
        # (short line containing only hex/alphanumeric — typical CSRF token pattern)
        import re as _re
        _token_re = _re.compile(r"[a-f0-9]{16,}|[A-Za-z0-9+/=]{24,}")
        all_exclusive = true_exclusive | false_exclusive
        has_token_lines = any(
            _token_re.search(line.strip()) for line in all_exclusive
        )
        if not has_token_lines:
            return True

    return False


def _len_ratio(a: str, b: str) -> float:
    """
    Return the relative content-length difference between two responses.
    0.0 = same length, 1.0 = one is empty while the other is not.
    Useful for detecting boolean-blind injections where the page adds/removes
    a small snippet (e.g. "User ID exists" vs "User ID is MISSING").
    """
    la, lb = len(a), len(b)
    if la == 0 and lb == 0:
        return 0.0
    return abs(la - lb) / max(la, lb)


def _extract_marker(body: str, marker: str) -> str:
    """Extract a snippet around the marker from the response body.

    Returns up to 200 characters of context (10 before, 190 after) so that
    meaningful SQL output (version strings, table names) is captured rather
    than just the marker itself.
    """
    idx = body.find(marker)
    if idx == -1:
        return ""
    return body[max(0, idx - 10): idx + len(marker) + 190]


def _is_path_reflected(body: str, marker: str, payload: str) -> bool:
    """Return True if the marker appears to be a URL/path reflection rather than
    actual UNION output.

    This guards against apps that echo the full request URL (or query string) in
    a generic error page (e.g. "Unexpected path: /search?q=...MARKER...").  In
    such cases the marker is part of the injected value's URL-encoded form, not
    a SQL result.

    Detection heuristics:
    1. The marker is inside a ``<title>`` tag.
    2. The marker immediately follows URL-encoded SQL characters (``%27``, ``%29``,
       ``+UNION+``) — indicating the full payload was echoed verbatim.
    """
    import urllib.parse as _up
    body_lower = body.lower()

    # Heuristic 1: marker inside <title>
    title_start = body_lower.find("<title>")
    title_end   = body_lower.find("</title>")
    if title_start != -1 and title_end != -1:
        title_text = body[title_start:title_end]
        if marker.lower() in title_text.lower():
            return True

    # Heuristic 2: payload echoed verbatim (URL-encoded form)
    # Only fire if the URL-encoded form actually differs from the plain marker
    # (i.e. the marker itself contains characters that get percent-encoded).
    encoded_marker = _up.quote(marker)
    if encoded_marker != marker and encoded_marker in body:
        return True

    return False
