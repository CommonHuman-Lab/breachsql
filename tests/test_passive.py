# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for engine/_scanner/passive.py — passive header/DBMS hint checks."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from breachsql.engine._scanner.passive import run_passive_checks, _check_interesting_headers
from breachsql.engine.reporter import ScanResult


def _mock_response(headers: dict, body: str = "<html>OK</html>", status: int = 200):
    resp = MagicMock()
    resp.text = body
    resp.status_code = status
    resp.headers = headers
    return resp


class TestPassiveDbmsHinting:
    def test_x_powered_by_mysql_sets_dbms(self):
        result = ScanResult(target="https://x.com/")
        resp = _mock_response({"x-powered-by": "PHP/8.1.0 MySQL"})
        _check_interesting_headers("https://x.com/", resp, result)
        assert result.dbms_detected == "mysql"

    def test_x_powered_by_iis_sets_mssql(self):
        result = ScanResult(target="https://x.com/")
        resp = _mock_response({"x-powered-by": "ASP.NET"})
        _check_interesting_headers("https://x.com/", resp, result)
        assert result.dbms_detected == "mssql"

    def test_server_postgres_sets_dbms(self):
        result = ScanResult(target="https://x.com/")
        resp = _mock_response({"server": "PostgreSQL/14"})
        _check_interesting_headers("https://x.com/", resp, result)
        assert result.dbms_detected == "postgres"

    def test_x_aspnet_version_header_name_sets_mssql(self):
        """x-aspnet-version header value is a version number, not 'asp'.
        DBMS hint must be triggered by the header *name*, not the value."""
        result = ScanResult(target="https://x.com/")
        resp = _mock_response({"x-aspnet-version": "4.0.30319"})
        _check_interesting_headers("https://x.com/", resp, result)
        assert result.dbms_detected == "mssql", (
            "x-aspnet-version header should hint MSSQL regardless of its value"
        )

    def test_x_aspnetmvc_version_header_name_sets_mssql(self):
        result = ScanResult(target="https://x.com/")
        resp = _mock_response({"x-aspnetmvc-version": "5.2.9"})
        _check_interesting_headers("https://x.com/", resp, result)
        assert result.dbms_detected == "mssql"

    def test_no_hint_when_dbms_already_detected(self):
        """Should not overwrite an already-detected DBMS."""
        result = ScanResult(target="https://x.com/")
        result.dbms_detected = "postgres"
        resp = _mock_response({"x-powered-by": "ASP.NET"})
        _check_interesting_headers("https://x.com/", resp, result)
        assert result.dbms_detected == "postgres"

    def test_no_hint_from_unrecognised_header_value(self):
        result = ScanResult(target="https://x.com/")
        resp = _mock_response({"x-powered-by": "Ruby/3.2"})
        _check_interesting_headers("https://x.com/", resp, result)
        assert result.dbms_detected is None

    def test_run_passive_checks_with_none_response(self):
        """run_passive_checks must handle None seed_resp gracefully."""
        result = ScanResult(target="https://x.com/")
        run_passive_checks("https://x.com/", None, MagicMock(), result)
        # No crash, no findings
        assert result.dbms_detected is None
