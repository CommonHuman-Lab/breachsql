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
    get_concat_payloads,
    get_substring_probes,
    make_substring_payload,
    get_db_contents_payloads,
    get_stacked_payloads,
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


# ---------------------------------------------------------------------------
# String concatenation payloads
# ---------------------------------------------------------------------------

class TestGetConcatPayloads:
    def test_mysql_uses_concat_function(self):
        assert any("CONCAT" in p for p in get_concat_payloads("mysql"))

    def test_mssql_uses_plus_operator(self):
        assert any("'foo'+'bar'" in p for p in get_concat_payloads("mssql"))

    def test_postgres_uses_pipe_operator(self):
        assert any("||" in p for p in get_concat_payloads("postgres"))

    def test_sqlite_uses_pipe_operator(self):
        assert any("||" in p for p in get_concat_payloads("sqlite"))

    def test_oracle_uses_pipe_operator_with_dual(self):
        payloads = get_concat_payloads("oracle")
        assert any("||" in p for p in payloads)
        assert any("dual" in p.lower() for p in payloads)

    def test_mariadb_uses_concat_function(self):
        assert any("CONCAT" in p for p in get_concat_payloads("mariadb"))

    def test_auto_has_all_syntax_forms(self):
        payloads = get_concat_payloads("auto")
        assert any("CONCAT" in p for p in payloads)
        assert any("||" in p for p in payloads)
        assert any("+" in p for p in payloads)

    def test_unknown_dbms_falls_back_to_auto(self):
        assert len(get_concat_payloads("unknowndb")) > 0


# ---------------------------------------------------------------------------
# Substring probes
# ---------------------------------------------------------------------------

class TestGetSubstringProbes:
    def test_mysql_uses_substring_or_mid(self):
        probes = get_substring_probes("mysql")
        assert any("SUBSTRING" in p or "MID" in p for p in probes)

    def test_sqlite_uses_substr(self):
        assert any("SUBSTR" in p for p in get_substring_probes("sqlite"))

    def test_oracle_uses_substr(self):
        assert any("SUBSTR" in p for p in get_substring_probes("oracle"))

    def test_all_dialects_have_probes(self):
        for dbms in ("mysql", "mariadb", "mssql", "postgres", "sqlite", "oracle"):
            assert len(get_substring_probes(dbms)) > 0, f"No substring probes for {dbms}"


class TestMakeSubstringPayload:
    def test_contains_position(self):
        assert ",3," in make_substring_payload("mysql", "expr", 3, "a")

    def test_contains_ordinal(self):
        assert str(ord("A")) in make_substring_payload("mysql", "expr", 1, "A")

    def test_sqlite_uses_substr(self):
        assert "SUBSTR" in make_substring_payload("sqlite", "expr", 1, "x")

    def test_postgres_uses_substring(self):
        assert "SUBSTRING" in make_substring_payload("postgres", "expr", 1, "x")


# ---------------------------------------------------------------------------
# Database contents enumeration payloads
# ---------------------------------------------------------------------------

class TestGetDbContentsPayloads:
    def test_mysql_tables_use_information_schema(self):
        assert any("information_schema" in p.lower() for p in get_db_contents_payloads("mysql", "tables"))

    def test_mssql_tables_use_information_schema_or_sysobjects(self):
        payloads = get_db_contents_payloads("mssql", "tables")
        assert any("information_schema" in p.lower() or "sysobjects" in p.lower() for p in payloads)

    def test_postgres_tables_use_information_schema_or_pg_tables(self):
        payloads = get_db_contents_payloads("postgres", "tables")
        assert any("information_schema" in p.lower() or "pg_tables" in p.lower() for p in payloads)

    def test_sqlite_tables_use_sqlite_master(self):
        assert any("sqlite_master" in p.lower() for p in get_db_contents_payloads("sqlite", "tables"))

    def test_oracle_tables_use_all_tables(self):
        payloads = get_db_contents_payloads("oracle", "tables")
        assert any("all_tables" in p.lower() or "user_tables" in p.lower() for p in payloads)

    def test_mariadb_tables_use_information_schema(self):
        assert any("information_schema" in p.lower() for p in get_db_contents_payloads("mariadb", "tables"))

    def test_columns_target_all_dialects(self):
        for dbms in ("mysql", "mssql", "postgres", "oracle", "sqlite"):
            assert len(get_db_contents_payloads(dbms, "columns")) > 0, f"No column payloads for {dbms}"

    def test_unknown_dbms_returns_empty(self):
        assert get_db_contents_payloads("unknowndb", "tables") == []


# ---------------------------------------------------------------------------
# OOB: MariaDB + DNS data exfiltration
# ---------------------------------------------------------------------------

class TestMariadbOob:
    def test_not_empty(self):
        assert len(get_oob_payloads("mariadb", "http://cb.example.com")) > 0

    def test_uses_load_file(self):
        assert any("LOAD_FILE" in p for p in get_oob_payloads("mariadb", "http://cb.example.com"))

    def test_callback_substituted(self):
        assert any("mycallback.io" in p for p in get_oob_payloads("mariadb", "http://mycallback.io"))


class TestDnsExfil:
    def test_mysql_embeds_version_in_hostname(self):
        assert any("VERSION()" in p for p in get_oob_payloads("mysql", "http://cb.example.com"))

    def test_mssql_embeds_query_output_in_unc_path(self):
        payloads = get_oob_payloads("mssql", "http://cb.example.com")
        assert any("@@version" in p.lower() or "table_name" in p.lower() for p in payloads)

    def test_postgres_has_version_exfil(self):
        payloads = get_oob_payloads("postgres", "http://cb.example.com")
        assert any("version()" in p.lower() for p in payloads)
        assert len(payloads) >= 2

    def test_oracle_has_utl_inaddr_exfil(self):
        payloads = get_oob_payloads("oracle", "http://cb.example.com")
        assert any("UTL_INADDR" in p or "v$version" in p for p in payloads)

    def test_oracle_has_xxe_payload(self):
        payloads = get_oob_payloads("oracle", "http://cb.example.com")
        assert any("EXTRACTVALUE" in p and "xml" in p.lower() for p in payloads)

    def test_oracle_utl_http_request_present(self):
        assert any("UTL_HTTP.REQUEST" in p for p in get_oob_payloads("oracle", "http://cb.example.com"))


# ---------------------------------------------------------------------------
# Stacked query payloads
# ---------------------------------------------------------------------------

class TestGetStackedPayloads:
    def test_mysql_has_payloads(self):
        assert len(get_stacked_payloads("mysql", risk=1)) > 0

    def test_mssql_has_waitfor(self):
        assert any("WAITFOR" in p for p in get_stacked_payloads("mssql", risk=1))

    def test_postgres_has_payloads(self):
        assert len(get_stacked_payloads("postgres", risk=1)) > 0

    def test_sqlite_has_payloads(self):
        assert len(get_stacked_payloads("sqlite", risk=1)) > 0

    def test_oracle_returns_empty(self):
        assert get_stacked_payloads("oracle", risk=3) == []

    def test_xp_cmdshell_excluded_at_risk1(self):
        assert not any("xp_cmdshell" in p.lower() for p in get_stacked_payloads("mssql", risk=1))

    def test_xp_cmdshell_included_at_risk3(self):
        assert any("xp_cmdshell" in p.lower() for p in get_stacked_payloads("mssql", risk=3))
