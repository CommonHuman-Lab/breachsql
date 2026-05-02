# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for engine/_scanner/active.py — error-based, boolean, union detection."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from breachsql.engine._scanner.active import (
    scan_param,
    _detect_db_error,
    _diff_score,
    _extract_marker,
)
from breachsql.engine._scanner.options import ScanOptions
from breachsql.engine.reporter import ScanResult


def _mock_injector(responses: dict[str, str] | None = None):
    """Build a minimal mock Injector that returns canned responses."""
    injector = MagicMock()
    responses = responses or {}

    def _get_resp(text: str):
        r = MagicMock()
        r.text = text
        r.status_code = 200
        return r

    def _inject_get(url, param, value):
        key = value.strip()[:20]
        text = responses.get(key, "<html>OK</html>")
        return _get_resp(text)

    def _post(url, data=None):
        val = (data or {}).get(list((data or {}).keys())[0] if data else "", "")
        key = str(val).strip()[:20]
        text = responses.get(key, "<html>OK</html>")
        return _get_resp(text)

    injector.inject_get.side_effect = _inject_get
    injector.post.side_effect = _post
    injector.get_params.return_value = ["q"]
    injector.request_count = 0
    return injector


def _surface(url="https://x.com/?q=1", method="GET", param="q"):
    return {"url": url, "method": method, "params": {param: "1"}, "single_param": param}


class TestDetectDbError:
    def test_mysql_error(self):
        dbms, evidence = _detect_db_error(
            "You have an error in your SQL syntax near '1'"
        )
        assert dbms == "mysql"
        assert evidence != ""

    def test_mssql_error(self):
        dbms, evidence = _detect_db_error(
            "Incorrect syntax near the keyword 'AND'. Microsoft SQL Server"
        )
        assert dbms == "mssql"

    def test_postgres_error(self):
        dbms, evidence = _detect_db_error(
            "ERROR: invalid input syntax for type integer"
        )
        assert dbms == "postgres"

    def test_sqlite_error(self):
        dbms, evidence = _detect_db_error(
            'near "\'": syntax error'
        )
        assert dbms == "sqlite"

    def test_generic_error(self):
        dbms, evidence = _detect_db_error("SQL Error: syntax error in query")
        assert dbms in ("generic", "mysql", "mssql", "postgres", "sqlite")

    def test_no_error(self):
        dbms, evidence = _detect_db_error("<html><body>Normal page</body></html>")
        assert dbms == ""
        assert evidence == ""


class TestDiffScore:
    def test_identical_strings_score_zero(self):
        assert _diff_score("hello", "hello") == pytest.approx(0.0)

    def test_completely_different_score_one(self):
        score = _diff_score("aaaa", "bbbb")
        assert score > 0.9

    def test_slightly_different(self):
        a = "<html>You are logged in as admin</html>"
        b = "<html>You are not logged in</html>"
        score = _diff_score(a, b)
        assert 0.0 < score < 1.0


class TestExtractMarker:
    def test_found(self):
        body = "<td>before BreachSQL_abc123 after</td>"
        result = _extract_marker(body, "BreachSQL_abc123")
        assert "BreachSQL_abc123" in result

    def test_not_found(self):
        result = _extract_marker("<html>nothing</html>", "BreachSQL_xyz")
        assert result == ""


class TestTestParam:
    def test_error_based_detection(self):
        """Should detect MySQL error in response and append an ErrorBasedFinding."""
        mysql_error = "You have an error in your SQL syntax near '1'"
        injector = _mock_injector({"'": mysql_error})
        opts = ScanOptions(technique="E", dbms="mysql", level=1)
        result = ScanResult(target="https://x.com/")

        scan_param(_surface(), ["none"], opts, injector, result)

        assert len(result.error_based) == 1
        assert result.error_based[0].dbms == "mysql"

    def test_boolean_detection(self):
        """Should detect boolean SQLi when true/false responses diverge."""
        injector = _mock_injector({
            "' AND '1'='1": "<html>Welcome admin</html>",
            "' AND '1'='2": "<html>Error: invalid login</html>",
            "": "<html>Welcome admin</html>",
            "1":  "<html>Welcome admin</html>",
        })
        opts = ScanOptions(technique="B", level=1)
        result = ScanResult(target="https://x.com/")

        scan_param(_surface(), ["none"], opts, injector, result)

        assert len(result.boolean_based) == 1

    def test_no_finding_clean_response(self):
        """No findings if responses are all identical (no SQLi)."""
        injector = _mock_injector()
        opts = ScanOptions(technique="EB", level=1)
        result = ScanResult(target="https://x.com/")

        scan_param(_surface(), ["none"], opts, injector, result)

        assert result.total_findings == 0

    def test_technique_e_only_runs_error(self):
        """With technique='E', boolean tests should not run."""
        injector = _mock_injector()
        opts = ScanOptions(technique="E", level=1)
        result = ScanResult(target="https://x.com/")

        with patch("breachsql.engine._scanner.active._test_boolean") as mock_bool:
            scan_param(_surface(), ["none"], opts, injector, result)
            mock_bool.assert_not_called()

    def test_union_requires_level2(self):
        """Union detection should not run at level=1."""
        injector = _mock_injector()
        opts = ScanOptions(technique="U", level=1)
        result = ScanResult(target="https://x.com/")

        with patch("breachsql.engine._scanner.active._test_union") as mock_union:
            scan_param(_surface(), ["none"], opts, injector, result)
            mock_union.assert_not_called()

    def test_union_runs_at_level2(self):
        """Union detection should run at level=2."""
        injector = _mock_injector()
        opts = ScanOptions(technique="U", level=2)
        result = ScanResult(target="https://x.com/")

        with patch("breachsql.engine._scanner.active._test_union") as mock_union:
            scan_param(_surface(), ["none"], opts, injector, result)
            mock_union.assert_called_once()
