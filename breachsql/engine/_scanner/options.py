# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Scan configuration for BreachSQL."""

from __future__ import annotations

import warnings
from typing import Any

_VALID_TECHNIQUE_CHARS = frozenset("EBTUSO")


class ScanOptions:
    def __init__(
        self,
        # Shared
        crawl:            bool              = False,
        data:             str               = "",
        headers:          dict[str, str] | None = None,
        cookies:          str               = "",
        proxy:            str               = "",
        threads:          int               = 5,
        timeout:          int               = 15,
        level:            int               = 1,
        max_pages:        int               = 50,
        max_depth:        int               = 3,
        delay:            float             = 0.0,
        output:           str               = "",
        exclude_patterns: list[Any] | None  = None,
        # SQLi-specific
        dbms:             str               = "auto",   # auto|mysql|mssql|postgres|sqlite
        technique:        str               = "EBTUO",  # E B T U O
        oob_callback:     str               = "",
        time_threshold:   int               = 4,        # seconds
        risk:             int               = 1,        # 1-3
        second_url:       str               = "",       # read response from different URL
        max_union_cols:   int               = 20,       # max columns to probe in UNION detection
        path_params:      list[str] | None  = None,     # path segment names to inject
    ) -> None:
        # Shared
        self.crawl            = crawl
        self.data             = data.strip()
        self.headers          = headers or {}
        self.cookies          = cookies.strip()
        self.proxy            = proxy.strip()
        self.threads          = max(1, min(threads, 20))
        self.timeout          = max(5, min(timeout, 120))
        self.level            = max(1, min(level, 3))
        self.max_pages        = max_pages
        self.max_depth        = max_depth
        self.delay            = max(0.0, delay)
        self.output           = output.strip()
        self.exclude_patterns: list[Any] = exclude_patterns or []
        # SQLi-specific
        self.dbms             = dbms.lower().strip()
        technique_upper = technique.upper()
        unknown_chars = set(technique_upper) - _VALID_TECHNIQUE_CHARS
        if unknown_chars:
            warnings.warn(
                f"Unknown technique letter(s) ignored: {''.join(sorted(unknown_chars))}. "
                f"Valid letters are: E B T U S O",
                UserWarning,
                stacklevel=2,
            )
        # Keep only valid letters, preserving the original order
        self.technique        = "".join(c for c in technique_upper if c in _VALID_TECHNIQUE_CHARS)
        self.oob_callback     = oob_callback.strip()
        self.time_threshold   = max(1, min(time_threshold, 30))
        self.risk             = max(1, min(risk, 3))
        self.second_url       = second_url.strip()  # if set, read responses from here
        self.max_union_cols   = max(1, min(max_union_cols, 100))
        self.path_params      = path_params or []

    # Convenience: check which techniques are enabled
    @property
    def use_error(self)   -> bool: return "E" in self.technique
    @property
    def use_boolean(self) -> bool: return "B" in self.technique
    @property
    def use_time(self)    -> bool: return "T" in self.technique
    @property
    def use_union(self)   -> bool: return "U" in self.technique
    @property
    def use_stacked(self) -> bool: return "S" in self.technique
    @property
    def use_oob(self)     -> bool: return "O" in self.technique and bool(self.oob_callback)
