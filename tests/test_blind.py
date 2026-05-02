# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for engine/_scanner/blind.py — time-based and OOB detection."""

from __future__ import annotations

from unittest.mock import MagicMock, patch
import time

import pytest

from breachsql.engine._scanner.blind import (
    run_time_based,
    run_oob,
    _infer_dbms_from_payload,
)
from breachsql.engine._scanner.options import ScanOptions
from breachsql.engine.reporter import ScanResult


def _surface(url="https://x.com/?id=1", method="GET", param="id"):
    return {"url": url, "method": method, "params": {param: "1"}, "single_param": param}


def _mock_injector_with_delay(delay: float = 0.0):
    """Injector whose inject_get sleeps for *delay* seconds."""
    injector = MagicMock()

    def _inject_get(url, param, value):
        if delay > 0:
            time.sleep(delay)
        r = MagicMock()
        r.text = "<html>OK</html>"
        r.status_code = 200
        return r

    injector.inject_get.side_effect = _inject_get
    injector.post.side_effect = lambda url, data=None: _inject_get(url, "", "")
    return injector


class TestInferDbms:
    def test_mysql(self):
        assert _infer_dbms_from_payload("' AND SLEEP(4)--") == "mysql"

    def test_mssql(self):
        assert _infer_dbms_from_payload("WAITFOR DELAY '0:0:4'") == "mssql"

    def test_postgres(self):
        assert _infer_dbms_from_payload("pg_sleep(4)") == "postgres"

    def test_sqlite(self):
        assert _infer_dbms_from_payload("randomblob(40000000)") == "sqlite"

    def test_unknown(self):
        assert _infer_dbms_from_payload("some other payload") == "unknown"


class TestTestTimeBased:
    def test_no_finding_fast_response(self):
        """Fast responses should not produce time-based findings."""
        injector = _mock_injector_with_delay(0.0)
        opts = ScanOptions(technique="T", time_threshold=4, dbms="mysql")
        result = ScanResult(target="https://x.com/")
        run_time_based(_surface(), ["none"], opts, injector, result)
        assert len(result.time_based) == 0

    def test_oob_not_called_without_callback(self):
        """OOB should silently exit if no callback is configured."""
        injector = MagicMock()
        opts = ScanOptions(technique="O", oob_callback="")
        result = ScanResult(target="https://x.com/")
        run_oob(_surface(), ["none"], opts, injector, result)
        assert len(result.oob) == 0
        injector.inject_get.assert_not_called()


class TestTestOob:
    def test_oob_appends_finding(self):
        """OOB inject should append an OOBFinding even without callback confirmation."""
        injector = MagicMock()
        r = MagicMock()
        r.text = "<html>OK</html>"
        injector.inject_get.return_value = r

        opts = ScanOptions(technique="O", oob_callback="http://cb.example.com", dbms="mssql")
        result = ScanResult(target="https://x.com/")

        run_oob(_surface(), ["none"], opts, injector, result)

        assert len(result.oob) == 1
        assert result.oob[0].callback_url == "http://cb.example.com"

    def test_oob_uses_correct_param(self):
        injector = MagicMock()
        r = MagicMock()
        r.text = "<html>OK</html>"
        injector.inject_get.return_value = r

        opts = ScanOptions(technique="O", oob_callback="http://cb.io", dbms="mssql")
        result = ScanResult(target="https://x.com/")
        surface = _surface(param="user_id")

        run_oob(surface, ["none"], opts, injector, result)

        assert result.oob[0].parameter == "user_id"

    def test_oob_sqlite_no_payloads(self):
        """SQLite has no OOB capability — no finding should be appended."""
        injector = MagicMock()
        opts = ScanOptions(technique="O", oob_callback="http://cb.io", dbms="sqlite")
        # Simulate detected sqlite
        result = ScanResult(target="https://x.com/")
        result.dbms_detected = "sqlite"

        run_oob(_surface(), ["none"], opts, injector, result)
        # No payloads → no finding
        assert len(result.oob) == 0
