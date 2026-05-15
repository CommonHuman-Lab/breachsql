# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for engine/_scanner/extract.py — blind data extraction engine."""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

import pytest

from breachsql.engine._scanner.extract import extract_value, extract_via_union
from breachsql.engine._scanner.options import ScanOptions
from breachsql.engine.reporter import UnionFinding


def _surface(url="https://x.com/?id=1", method="GET", param="id"):
    return {"url": url, "method": method, "params": {param: "1"}, "single_param": param}


class TestExtractValue:
    def test_extracts_known_string_boolean(self):
        """Boolean extraction must recover a known string via OR-based single probe."""
        target = "abc"
        _baseline = "<html>not-found</html>"
        _found    = "<html>found</html>"

        def _fetch_side(injector, url, method, params, param, value,
                        second_url="", json_body=False, path_index=0):
            m = re.search(r"ASCII\(SUBSTRING\(\((.+?)\),(\d+),1\)\)>(\d+)", value or "")
            if not m:
                return _baseline
            pos       = int(m.group(2))
            threshold = int(m.group(3))
            actual_ord = ord(target[pos - 1]) if pos <= len(target) else 0
            # OR fires → all rows returned (differs from baseline) when condition true
            return _found if actual_ord > threshold else _baseline

        with patch("breachsql.engine._scanner.extract._fetch", side_effect=_fetch_side):
            opts = ScanOptions(dbms="mysql")
            extracted = extract_value(
                expr="SELECT 'abc'",
                surface=_surface(),
                evasions=["none"],
                opts=opts,
                injector=MagicMock(),
                baseline=_baseline,
                mode="boolean",
            )
        assert extracted == "abc"

    def test_boolean_payloads_use_or_prefix(self):
        """All boolean extraction probes must use OR injection, not AND."""
        seen = []

        def _capture(injector, url, method, params, param, value,
                     second_url="", json_body=False, path_index=0):
            if value:
                seen.append(value)
            return "<html>not-found</html>"

        with patch("breachsql.engine._scanner.extract._fetch", side_effect=_capture):
            opts = ScanOptions(dbms="mysql")
            extract_value(
                expr="VERSION()",
                surface=_surface(),
                evasions=["none"],
                opts=opts,
                injector=MagicMock(),
                baseline="<html>not-found</html>",
                mode="boolean",
            )

        assert len(seen) > 0
        for payload in seen:
            assert "' OR " in payload, f"Expected OR injection, got: {payload!r}"
            assert "' AND " not in payload, f"Unexpected AND injection: {payload!r}"

    def test_end_of_string_stops_extraction(self):
        """Extraction must stop at end-of-string (ASCII 0) without appending junk."""
        target = "hi"
        _baseline = "empty"
        _found    = "found"

        def _fetch_side(injector, url, method, params, param, value,
                        second_url="", json_body=False, path_index=0):
            m = re.search(r"ASCII\(SUBSTRING\(\((.+?)\),(\d+),1\)\)>(\d+)", value or "")
            if not m:
                return _baseline
            pos       = int(m.group(2))
            threshold = int(m.group(3))
            actual_ord = ord(target[pos - 1]) if pos <= len(target) else 0
            return _found if actual_ord > threshold else _baseline

        with patch("breachsql.engine._scanner.extract._fetch", side_effect=_fetch_side):
            result = extract_value(
                expr="SELECT 'hi'",
                surface=_surface(),
                evasions=["none"],
                opts=ScanOptions(dbms="mysql"),
                injector=MagicMock(),
                baseline=_baseline,
                mode="boolean",
            )

        assert result == "hi", f"Expected 'hi', got {result!r}"

    def test_returns_empty_when_no_signal(self):
        """When both responses are identical (no boolean channel), return empty string."""
        def _no_signal(injector, url, method, params, param, value,
                       second_url="", json_body=False, path_index=0):
            return "<html>same</html>"

        with patch("breachsql.engine._scanner.extract._fetch", side_effect=_no_signal):
            opts = ScanOptions(dbms="mysql")
            extracted = extract_value(
                expr="NULL",
                surface=_surface(),
                evasions=["none"],
                opts=opts,
                injector=MagicMock(),
                baseline="<html>same</html>",
                mode="boolean",
            )
        assert extracted == ""

    def test_sqlite_uses_substr(self):
        """SQLite extraction payloads must use SUBSTR, not SUBSTRING."""
        seen_payloads = []

        def _capture(injector, url, method, params, param, value,
                     second_url="", json_body=False, path_index=0):
            if value is not None:
                seen_payloads.append(value)
            return "<html>false</html>"

        with patch("breachsql.engine._scanner.extract._fetch", side_effect=_capture):
            opts = ScanOptions(dbms="sqlite")
            extract_value(
                expr="SELECT 'x'",
                surface=_surface(),
                evasions=["none"],
                opts=opts,
                injector=MagicMock(),
                baseline="<html>false</html>",
                mode="boolean",
            )

        assert any("SUBSTR(" in p and "SUBSTRING(" not in p for p in seen_payloads)

    def test_oracle_uses_substr(self):
        """Oracle extraction payloads must use SUBSTR, not SUBSTRING."""
        seen_payloads = []

        def _capture(injector, url, method, params, param, value,
                     second_url="", json_body=False, path_index=0):
            if value is not None:
                seen_payloads.append(value)
            return "<html>false</html>"

        with patch("breachsql.engine._scanner.extract._fetch", side_effect=_capture):
            opts = ScanOptions(dbms="oracle")
            extract_value(
                expr="SELECT 'x' FROM dual",
                surface=_surface(),
                evasions=["none"],
                opts=opts,
                injector=MagicMock(),
                baseline="<html>false</html>",
                mode="boolean",
            )

        assert any("SUBSTR(" in p for p in seen_payloads)


class TestTimeBlindPayloads:
    """Verify per-DBMS time-blind extraction payload syntax."""

    def _collect_time_payloads(self, dbms: str) -> list:
        """Run extract_value in time mode and collect all _timed_fetch payloads."""
        seen = []

        def _timed(injector, url, method, params, param, value,
                   second_url="", json_body=False, path_index=0):
            seen.append(value)
            return 0.0  # always fast → extraction terminates quickly

        with patch("breachsql.engine._scanner.extract._timed_fetch", side_effect=_timed):
            opts = ScanOptions(dbms=dbms, time_threshold=4)
            extract_value(
                expr="VERSION()",
                surface=_surface(),
                evasions=["none"],
                opts=opts,
                injector=MagicMock(),
                baseline="",
                mode="time",
            )
        return seen

    def test_mysql_uses_if_sleep(self):
        payloads = self._collect_time_payloads("mysql")
        assert any("IF(" in p and "SLEEP(" in p for p in payloads)

    def test_postgres_uses_pg_sleep(self):
        payloads = self._collect_time_payloads("postgres")
        assert any("pg_sleep(" in p for p in payloads)

    def test_sqlite_uses_randomblob(self):
        payloads = self._collect_time_payloads("sqlite")
        assert any("randomblob(" in p.lower() or "WITH RECURSIVE" in p for p in payloads)

    def test_mssql_uses_stacked_waitfor(self):
        """MSSQL time-blind must use stacked IF ... WAITFOR DELAY, not a SELECT subquery."""
        payloads = self._collect_time_payloads("mssql")
        for p in payloads:
            # Must be stacked (starts with ';') and use IF + WAITFOR
            assert "SELECT WAITFOR" not in p, (
                f"MSSQL payload must not use SELECT WAITFOR subquery: {p}"
            )
        assert any("WAITFOR DELAY" in p and p.startswith("'") and "IF " in p
                   for p in payloads)


# ---------------------------------------------------------------------------
# extract_via_union
# ---------------------------------------------------------------------------

def _union_finding(payload="')) UNION SELECT 'BreachSQL_marker',2-- -"):
    return UnionFinding(
        url="https://x.com/search",
        parameter="q",
        method="GET",
        payload=payload,
        column_count=2,
    )


def _surface(url="https://x.com/search", param="q"):
    return {"url": url, "method": "GET", "params": {param: ""}, "single_param": param}


class TestExtractViaUnion:
    def _run(self, dbms, resp_text, payload=None):
        finding = _union_finding(payload or "')) UNION SELECT 'BreachSQL_marker',2-- -")
        with patch("breachsql.engine._scanner.extract._fetch", return_value=resp_text):
            return extract_via_union(
                expr="VERSION()",
                union_finding=finding,
                surface=_surface(),
                evasions=["none"],
                opts=ScanOptions(dbms=dbms),
                injector=MagicMock(),
            )

    def test_mysql_uses_concat_function(self):
        seen = []
        finding = _union_finding()
        def _capture(injector, url, method, params, param, value, **kw):
            seen.append(value)
            return ""
        with patch("breachsql.engine._scanner.extract._fetch", side_effect=_capture):
            extract_via_union(
                expr="VERSION()",
                union_finding=finding,
                surface=_surface(),
                evasions=["none"],
                opts=ScanOptions(dbms="mysql"),
                injector=MagicMock(),
            )
        assert any("CONCAT(" in p for p in seen)

    def test_sqlite_uses_pipe_concat(self):
        seen = []
        finding = _union_finding()
        def _capture(injector, url, method, params, param, value, **kw):
            seen.append(value)
            return ""
        with patch("breachsql.engine._scanner.extract._fetch", side_effect=_capture):
            extract_via_union(
                expr="sqlite_version()",
                union_finding=finding,
                surface=_surface(),
                evasions=["none"],
                opts=ScanOptions(dbms="sqlite"),
                injector=MagicMock(),
            )
        assert any("||" in p for p in seen)

    def test_postgres_uses_pipe_concat(self):
        seen = []
        finding = _union_finding()
        def _capture(injector, url, method, params, param, value, **kw):
            seen.append(value)
            return ""
        with patch("breachsql.engine._scanner.extract._fetch", side_effect=_capture):
            extract_via_union(
                expr="version()",
                union_finding=finding,
                surface=_surface(),
                evasions=["none"],
                opts=ScanOptions(dbms="postgres"),
                injector=MagicMock(),
            )
        assert any("||" in p for p in seen)

    def test_mssql_uses_plus_concat(self):
        seen = []
        finding = _union_finding()
        def _capture(injector, url, method, params, param, value, **kw):
            seen.append(value)
            return ""
        with patch("breachsql.engine._scanner.extract._fetch", side_effect=_capture):
            extract_via_union(
                expr="@@version",
                union_finding=finding,
                surface=_surface(),
                evasions=["none"],
                opts=ScanOptions(dbms="mssql"),
                injector=MagicMock(),
            )
        assert any("'BSQL_OUT_'+" in p for p in seen)

    def test_extracts_value_between_markers(self):
        marker_resp = "...BSQL_OUT_5.7.42_BSQL_END..."
        result = self._run("mysql", marker_resp)
        assert result == "5.7.42"

    def test_returns_empty_when_no_marker_in_response(self):
        result = self._run("mysql", "<html>no markers here</html>")
        assert result == ""

    def test_returns_empty_when_fetch_returns_none(self):
        result = self._run("mysql", None)
        assert result == ""

    def test_returns_empty_when_fetch_returns_empty_string(self):
        result = self._run("mysql", "")
        assert result == ""

    def test_returns_empty_when_payload_has_no_marker(self):
        finding = _union_finding(payload="')) UNION SELECT 1,2-- -")
        with patch("breachsql.engine._scanner.extract._fetch", return_value="anything"):
            result = extract_via_union(
                expr="VERSION()",
                union_finding=finding,
                surface=_surface(),
                evasions=["none"],
                opts=ScanOptions(dbms="mysql"),
                injector=MagicMock(),
            )
        assert result == ""

    def test_oracle_uses_pipe_concat(self):
        seen = []
        finding = _union_finding()
        def _capture(injector, url, method, params, param, value, **kw):
            seen.append(value)
            return ""
        with patch("breachsql.engine._scanner.extract._fetch", side_effect=_capture):
            extract_via_union(
                expr="banner FROM v$version",
                union_finding=finding,
                surface=_surface(),
                evasions=["none"],
                opts=ScanOptions(dbms="oracle"),
                injector=MagicMock(),
            )
        assert any("||" in p for p in seen)

    def test_auto_dbms_falls_back_to_mysql_concat(self):
        seen = []
        finding = _union_finding()
        def _capture(injector, url, method, params, param, value, **kw):
            seen.append(value)
            return ""
        with patch("breachsql.engine._scanner.extract._fetch", side_effect=_capture):
            extract_via_union(
                expr="VERSION()",
                union_finding=finding,
                surface=_surface(),
                evasions=["none"],
                opts=ScanOptions(dbms="auto"),
                injector=MagicMock(),
            )
        assert any("CONCAT(" in p for p in seen)
