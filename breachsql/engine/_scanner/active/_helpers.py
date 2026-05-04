# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
HTTP fetch helper and response comparison utilities for active scanning.
"""
from __future__ import annotations

import difflib
import re
from typing import Any, Dict, Optional

from ...log import get_logger
from ...http.injector import Injector

logger = get_logger("breachsql.active")

# diff score threshold above which we consider a boolean result confirmed
_BOOL_CONFIRM_THRESHOLD = 0.20
# diff score threshold above which we flag it as likely (lower confidence)
_BOOL_LIKELY_THRESHOLD  = 0.10
# content-length ratio difference that alone signals a boolean response divergence
_BOOL_LEN_RATIO_THRESHOLD = 0.02


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
            elif method.upper() == "COOKIE":
                injector.inject_cookie(url, param, injected[param])
            elif method.upper() == "HEADER":
                injector.inject_header(url, param, injected[param])
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
        elif method.upper() == "COOKIE":
            resp = injector.inject_cookie(url, param, injected[param])
        elif method.upper() == "HEADER":
            resp = injector.inject_header(url, param, injected[param])
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

        # Prepend the HTTP status code so that boolean detectors can see
        # status-code-based signals (e.g. 200 vs 404 as true/false indicator).
        # We use a sentinel prefix format that won't appear in normal responses.
        status_prefix = ""
        if hasattr(resp, "status_code"):
            status_prefix = f"__HTTP_STATUS_{resp.status_code}__\n"
        return status_prefix + resp.text
    except Exception as exc:
        logger.debug("Request error for %s param=%s: %s", url, param, exc)
        return None


_STATUS_SENTINEL_RE = re.compile(r"^__HTTP_STATUS_\d+__\n", re.MULTILINE)


def strip_status_sentinel(text: str) -> str:
    """Remove the HTTP status sentinel prefix added by _fetch before storing evidence."""
    return _STATUS_SENTINEL_RE.sub("", text, count=1)


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
    "User ID is MISSING") while being otherwise byte-for-byte identical.
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
        _token_re = re.compile(r"[a-f0-9]{16,}|[A-Za-z0-9+/=]{24,}")
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

    Detection heuristics:
    1. The marker is inside a ``<title>`` tag.
    2. The marker immediately follows URL-encoded SQL characters — indicating
       the full payload was echoed verbatim.
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
    encoded_marker = _up.quote(marker)
    if encoded_marker != marker and encoded_marker in body:
        return True

    return False
