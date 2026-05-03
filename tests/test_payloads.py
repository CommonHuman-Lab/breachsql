# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for engine/_scanner/payloads.py"""

from __future__ import annotations

import pytest

from breachsql.engine._scanner.payloads import (
    BREACH_MARKER_PREFIX,
    make_marker,
    get_error_payloads,
    get_boolean_pairs,
    get_time_payloads,
    get_oob_payloads,
    apply_evasion,
    order_by_probes,
    union_null_probes,
    DB_ERROR_PATTERNS,
)
from breachsql.engine.http.waf_detect import (
    EVASION_NONE,
    EVASION_SQL_COMMENT,
    EVASION_SQL_CASE,
    EVASION_SQL_ENCODE,
    EVASION_SQL_WHITESPACE,
    EVASION_SQL_MULTILINE,
    EVASION_CASE_MIXING,
    EVASION_DOUBLE_ENCODE,
    EVASION_NULL_BYTE,
)


class TestMakeMarker:
    def test_starts_with_prefix(self):
        m = make_marker()
        assert m.startswith(BREACH_MARKER_PREFIX)

    def test_unique(self):
        markers = {make_marker() for _ in range(100)}
        assert len(markers) == 100


class TestGetErrorPayloads:
    def test_generic_always_included(self):
        payloads = get_error_payloads("auto", risk=1)
        assert "'" in payloads
        assert '"' in payloads

    def test_mysql_specific_included(self):
        payloads = get_error_payloads("mysql", risk=1)
        assert any("EXTRACTVALUE" in p or "UPDATEXML" in p for p in payloads)

    def test_mssql_xp_cmdshell_excluded_risk1(self):
        payloads = get_error_payloads("mssql", risk=1)
        assert not any("xp_cmdshell" in p.lower() for p in payloads)

    def test_mssql_xp_cmdshell_included_risk3(self):
        payloads = get_error_payloads("mssql", risk=3)
        assert any("xp_cmdshell" in p.lower() for p in payloads)

    def test_postgres_specific_included(self):
        payloads = get_error_payloads("postgres", risk=1)
        assert any("pg_sleep" in p or "CAST" in p for p in payloads)

    def test_sqlite_specific_included(self):
        payloads = get_error_payloads("sqlite", risk=1)
        assert any("sqlite_version" in p or "randomblob" in p for p in payloads)


class TestGetBooleanPairs:
    def test_returns_list_of_tuples(self):
        pairs = get_boolean_pairs(risk=1)
        assert all(isinstance(p, tuple) and len(p) == 2 for p in pairs)

    def test_risk2_has_more_pairs(self):
        pairs1 = get_boolean_pairs(risk=1)
        pairs2 = get_boolean_pairs(risk=2)
        assert len(pairs2) > len(pairs1)

    def test_true_differs_from_false(self):
        for pt, pf in get_boolean_pairs(risk=1):
            assert pt != pf


class TestGetTimePayloads:
    def test_mysql_contains_sleep(self):
        payloads = get_time_payloads("mysql", delay=4)
        assert any("SLEEP(4)" in p for p in payloads)

    def test_mssql_contains_waitfor(self):
        payloads = get_time_payloads("mssql", delay=4)
        assert any("WAITFOR" in p for p in payloads)

    def test_postgres_contains_pg_sleep(self):
        payloads = get_time_payloads("postgres", delay=4)
        assert any("pg_sleep(4)" in p for p in payloads)

    def test_sqlite_contains_randomblob(self):
        payloads = get_time_payloads("sqlite", delay=4)
        assert any("randomblob" in p for p in payloads)

    def test_delay_substituted(self):
        payloads = get_time_payloads("mysql", delay=7)
        assert any("7" in p for p in payloads)


class TestGetOobPayloads:
    def test_mysql_contains_load_file(self):
        payloads = get_oob_payloads("mysql", "http://cb.example.com")
        assert any("LOAD_FILE" in p for p in payloads)

    def test_mssql_contains_xp_dirtree(self):
        payloads = get_oob_payloads("mssql", "http://cb.example.com")
        assert any("xp_dirtree" in p for p in payloads)

    def test_callback_substituted(self):
        payloads = get_oob_payloads("mssql", "http://mycallback.io")
        assert any("mycallback.io" in p for p in payloads)

    def test_sqlite_returns_empty(self):
        payloads = get_oob_payloads("sqlite", "http://cb.example.com")
        assert payloads == []


class TestApplyEvasion:
    def test_none_returns_unchanged(self):
        p = "' AND 1=1--"
        assert apply_evasion(p, EVASION_NONE) == p

    def test_sql_comment_inserts_comment(self):
        result = apply_evasion("SELECT 1", EVASION_SQL_COMMENT)
        assert "/**/" in result

    def test_sql_encode_url_encodes(self):
        result = apply_evasion("' AND 1=1", EVASION_SQL_ENCODE)
        assert "%" in result
        assert "'" not in result

    def test_sql_whitespace_replaces_spaces(self):
        result = apply_evasion("SELECT 1 FROM t", EVASION_SQL_WHITESPACE)
        assert " " not in result

    def test_case_mixing_swaps_case(self):
        result = apply_evasion("SELECT", EVASION_CASE_MIXING)
        assert result == "select"

    def test_null_byte_appended(self):
        result = apply_evasion("payload", EVASION_NULL_BYTE)
        assert result.endswith("%00")

    def test_double_encode(self):
        result = apply_evasion("'", EVASION_DOUBLE_ENCODE)
        assert "%" in result


class TestUnionProbes:
    def test_order_by_count(self):
        probes = order_by_probes(max_cols=10)
        # Eight variants per column count: string+dash, string+hash,
        # single-paren+dash, single-paren+hash, double-paren+dash, double-paren+space-dash,
        # numeric+dash, numeric+hash
        assert len(probes) == 80
        assert "ORDER BY 1" in probes[0]
        assert "ORDER BY 10" in probes[-1]

    def test_union_null_probes_count(self):
        probes = union_null_probes(col_count=3, marker="TESTMARKER")
        # 3 positions × 3 variants (str literal, CAST, int-padded) × 8 comment/context combos = 72
        assert len(probes) == 72

    def test_union_null_probes_contain_marker(self):
        probes = union_null_probes(col_count=2, marker="MARK")
        assert all("MARK" in p for p in probes)

    def test_union_null_probes_null_count(self):
        probes = union_null_probes(col_count=4, marker="M")
        for p in probes:
            # Each probe should have 4 columns total (NULL or marker)
            cols_part = p.split("UNION SELECT")[1]
            # Strip comment suffix (-- - or #)
            cols_part = cols_part.split("-- -")[0].split("#")[0]
            assert cols_part.count(",") == 3  # 4 columns = 3 commas


class TestDbErrorPatterns:
    def test_all_dbms_present(self):
        for dbms in ("mysql", "mssql", "postgres", "sqlite", "generic"):
            assert dbms in DB_ERROR_PATTERNS
            assert len(DB_ERROR_PATTERNS[dbms]) > 0
