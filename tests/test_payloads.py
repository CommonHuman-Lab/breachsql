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
    get_dios_payloads,
    get_lfi_payloads,
    get_privesc_payloads,
    get_enum_payloads,
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
        # 16 variants per column count (8 original + 8 WAF bypass)
        assert len(probes) == 160
        assert "ORDER BY 1" in probes[0]

    def test_union_null_probes_count(self):
        probes = union_null_probes(col_count=3, marker="TESTMARKER")
        # 3 positions × 3 variants × (8 original + 8 WAF bypass) combos = 144
        assert len(probes) == 144

    def test_union_null_probes_contain_marker(self):
        probes = union_null_probes(col_count=2, marker="MARK")
        assert all("MARK" in p for p in probes)

    def test_union_null_probes_null_count(self):
        probes = union_null_probes(col_count=4, marker="M")
        # Only check probes that contain "UNION SELECT" (standard forms)
        standard = [p for p in probes if "UNION SELECT" in p]
        for p in standard:
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


# ---------------------------------------------------------------------------
# WAF bypass detection payload variants
# ---------------------------------------------------------------------------

class TestWafBypassErrorPayloads:
    def test_comment_terminator_variants_present(self):
        generic = get_error_payloads("generic", risk=1)
        assert any("--/**/-" in p for p in generic)
        assert any("--%0A-" in p for p in generic)
        assert any("--%23%0A-" in p for p in generic)
        assert any("--%23foo%0D%0A-" in p for p in generic)

    def test_waf_bypass_comment_count(self):
        generic = get_error_payloads("generic", risk=1)
        # At least the base set plus 14 WAF bypass comment terminators
        assert len(generic) >= 30


class TestWafBypassOrderBy:
    def test_group_by_variant_present(self):
        probes = order_by_probes(max_cols=2)
        assert any("GROUP BY" in p for p in probes)

    def test_comment_wrapped_order_by(self):
        probes = order_by_probes(max_cols=2)
        assert any("/**/ORDER/**/BY/**/" in p for p in probes)

    def test_conditional_comment_order_by(self):
        probes = order_by_probes(max_cols=2)
        assert any("/*!ORDER BY*/" in p for p in probes)

    def test_percent_encoded_newline_order_by(self):
        probes = order_by_probes(max_cols=2)
        assert any("%0Aorder%0Aby%0A" in p for p in probes)


class TestWafBypassUnionSelect:
    def test_union_all_select_present(self):
        probes = union_null_probes(col_count=2, marker="M")
        assert any("UNION ALL SELECT" in p for p in probes)

    def test_distinctrow_present(self):
        probes = union_null_probes(col_count=2, marker="M")
        assert any("Distinctrow" in p for p in probes)

    def test_and_null_union_present(self):
        probes = union_null_probes(col_count=2, marker="M")
        assert any("AnD null UNiON" in p for p in probes)

    def test_and_false_union_present(self):
        probes = union_null_probes(col_count=2, marker="M")
        assert any("And False Union" in p for p in probes)


class TestWafBypassTimePayloads:
    def test_xor_sleep_variant(self):
        payloads = get_time_payloads("mysql", delay=5)
        assert any("XOR(if(now()=sysdate(),sleep(" in p for p in payloads)

    def test_encoded_sleep_variant(self):
        payloads = get_time_payloads("mysql", delay=5)
        assert any("select*from(select(sleep(" in p for p in payloads)

    def test_comment_xor_sleep_variant(self):
        payloads = get_time_payloads("mysql", delay=5)
        assert any("/**/xor/**/sleep(" in p for p in payloads)

    def test_or_sleep_limit_variant(self):
        payloads = get_time_payloads("mysql", delay=5)
        assert any("or (sleep(" in p for p in payloads)


class TestBooleanPairsAltAnd:
    def test_char_zero_pair_present(self):
        pairs = get_boolean_pairs(risk=1)
        trues = [t for t, _ in pairs]
        assert any("char(0)" in t for t in trues)

    def test_mod_pair_present(self):
        pairs = get_boolean_pairs(risk=1)
        trues = [t for t, _ in pairs]
        assert any("mod(29,9)" in t for t in trues)

    def test_point_pair_present(self):
        pairs = get_boolean_pairs(risk=1)
        trues = [t for t, _ in pairs]
        assert any("point(29,9)" in t for t in trues)

    def test_false_union_pair_present(self):
        pairs = get_boolean_pairs(risk=1)
        trues = [t for t, _ in pairs]
        assert any("False" in t and ("UNION" in t or "Union" in t) for t in trues)


class TestGroupConcatDbContents:
    def test_mysql_tables_has_group_concat(self):
        payloads = get_db_contents_payloads("mysql", "tables")
        assert any("GROUP_CONCAT" in p for p in payloads)

    def test_mysql_columns_has_group_concat(self):
        payloads = get_db_contents_payloads("mysql", "columns")
        assert any("GROUP_CONCAT" in p for p in payloads)

    def test_mariadb_tables_has_group_concat(self):
        payloads = get_db_contents_payloads("mariadb", "tables")
        assert any("GROUP_CONCAT" in p for p in payloads)

    def test_mysql_waf_bypass_group_concat(self):
        payloads = get_db_contents_payloads("mysql", "tables")
        assert any("%53ELECT" in p or "%46ROM" in p for p in payloads)


class TestDiosPayloads:
    def test_returns_list(self):
        payloads = get_dios_payloads()
        assert isinstance(payloads, list)
        assert len(payloads) >= 3

    def test_contains_information_schema(self):
        payloads = get_dios_payloads()
        assert any("information_Schema" in p or "InFoRMAtiON_sCHeMa" in p for p in payloads)

    def test_contains_concat(self):
        payloads = get_dios_payloads()
        assert any("concat" in p.lower() for p in payloads)


class TestLfiPayloads:
    def test_returns_list(self):
        payloads = get_lfi_payloads()
        assert isinstance(payloads, list)
        assert len(payloads) >= 5

    def test_contains_etc_passwd(self):
        payloads = get_lfi_payloads()
        assert any("/etc/passwd" in p or "6574632f706173737764" in p for p in payloads)

    def test_contains_load_file(self):
        payloads = get_lfi_payloads()
        assert all("load_file" in p.lower() or "LOAD_FILE" in p for p in payloads)

    def test_contains_to_base64(self):
        payloads = get_lfi_payloads()
        assert any("TO_base64" in p for p in payloads)


class TestPrivescPayloads:
    def test_returns_list(self):
        payloads = get_privesc_payloads()
        assert isinstance(payloads, list)
        assert len(payloads) >= 4

    def test_contains_user_privileges(self):
        payloads = get_privesc_payloads()
        assert any("USER_PRIVILEGES" in p for p in payloads)

    def test_contains_file_priv(self):
        payloads = get_privesc_payloads()
        assert any("file_priv" in p for p in payloads)

    def test_contains_path_discovery(self):
        payloads = get_privesc_payloads()
        assert any("@@datadir" in p or "@@tmpdir" in p for p in payloads)

    def test_dumpfile_excluded_at_risk1(self):
        payloads = get_privesc_payloads(risk=1)
        assert not any("DUMPFILE" in p or "OUTFILE" in p for p in payloads)

    def test_dumpfile_included_at_risk3(self):
        payloads = get_privesc_payloads(risk=3)
        assert any("DUMPFILE" in p or "OUTFILE" in p for p in payloads)

    def test_super_priv_check_present(self):
        payloads = get_privesc_payloads()
        assert any("SUPER" in p or "Super_priv" in p for p in payloads)

    def test_schema_privileges_present(self):
        payloads = get_privesc_payloads()
        assert any("schema_privileges" in p for p in payloads)

    def test_hostname_present(self):
        payloads = get_privesc_payloads()
        assert any("@@hostname" in p for p in payloads)


# ---------------------------------------------------------------------------
# ENUM_PAYLOADS
# ---------------------------------------------------------------------------

class TestEnumPayloads:
    def test_version_category(self):
        payloads = get_enum_payloads("version")
        assert len(payloads) >= 3
        assert any("@@version" in p for p in payloads)

    def test_current_user_category(self):
        payloads = get_enum_payloads("current_user")
        assert any("user()" in p for p in payloads)
        assert any("system_user()" in p for p in payloads)

    def test_hostname_category(self):
        payloads = get_enum_payloads("hostname")
        assert any("@@hostname" in p for p in payloads)

    def test_current_database_category(self):
        payloads = get_enum_payloads("current_database")
        assert any("database()" in p for p in payloads)

    def test_list_databases_category(self):
        payloads = get_enum_payloads("list_databases")
        assert any("schemata" in p for p in payloads)

    def test_list_users_category(self):
        payloads = get_enum_payloads("list_users")
        assert any("mysql.user" in p or "user_privileges" in p for p in payloads)

    def test_password_hashes_category(self):
        payloads = get_enum_payloads("password_hashes")
        assert any("password" in p.lower() or "authentication_string" in p for p in payloads)

    def test_find_tables_by_column_category(self):
        payloads = get_enum_payloads("find_tables_by_column")
        assert any("column_name" in p and "TARGET_COLUMN" in p for p in payloads)

    def test_conditional_category_if(self):
        payloads = get_enum_payloads("conditional")
        assert any("IF(" in p for p in payloads)

    def test_conditional_category_case_when(self):
        payloads = get_enum_payloads("conditional")
        assert any("CASE WHEN" in p for p in payloads)

    def test_unknown_category_returns_empty(self):
        assert get_enum_payloads("nonexistent") == []


class TestBooleanPairsConditional:
    def test_if_pair_present(self):
        pairs = get_boolean_pairs(risk=1)
        trues = [t for t, _ in pairs]
        assert any("IF(1=1" in t for t in trues)

    def test_case_when_pair_present(self):
        pairs = get_boolean_pairs(risk=1)
        trues = [t for t, _ in pairs]
        assert any("CASE WHEN" in t for t in trues)

    def test_if_pair_differs(self):
        # True form uses 1=1, false form uses 1=2
        pairs = get_boolean_pairs(risk=1)
        if_pairs = [(t, f) for t, f in pairs if "IF(" in t]
        for t, f in if_pairs:
            assert t != f
