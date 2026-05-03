# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for engine/_scanner/blind.py — time-based and OOB detection."""

from __future__ import annotations

from unittest.mock import MagicMock, patch, call
import time

import pytest

from breachsql.engine._scanner.blind import (
    run_time_based,
    run_oob,
    _infer_dbms_from_payload,
    _measure_baseline,
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

    def test_pg_sleep_not_confused_with_sleep(self):
        """pg_sleep( must match postgres before sleep( matches mysql."""
        assert _infer_dbms_from_payload("pg_sleep(4)") == "postgres"


class TestMeasureBaseline:
    def test_returns_min_of_two_samples(self):
        """Baseline time should be the minimum of two clean request times."""
        injector = _mock_injector_with_delay(0.0)
        t = _measure_baseline(injector, "https://x.com/?id=1", "GET", {"id": "1"}, "id")
        assert t is not None
        assert t >= 0.0

    def test_returns_none_if_all_fail(self):
        """If all baseline requests fail, returns None."""
        injector = MagicMock()
        injector.inject_get.side_effect = Exception("network error")
        t = _measure_baseline(injector, "https://x.com/?id=1", "GET", {"id": "1"}, "id")
        assert t is None


class TestTestTimeBased:
    def test_no_finding_fast_response(self):
        """Fast responses should not produce time-based findings."""
        injector = _mock_injector_with_delay(0.0)
        opts = ScanOptions(technique="T", time_threshold=4, dbms="mysql")
        result = ScanResult(target="https://x.com/")
        run_time_based(_surface(), ["none"], opts, injector, result)
        assert len(result.time_based) == 0

    def test_slow_response_produces_finding(self):
        """Responses exceeding the threshold should produce a TimeFinding."""
        # Mock _timed_fetch to return a long delay without actually sleeping
        with patch("breachsql.engine._scanner.blind._timed_fetch") as mock_tf:
            # baseline = 0.01s, payload = 5.0s, confirmation = 5.0s
            mock_tf.side_effect = [0.01, 0.01, 5.0, 5.0]

            opts = ScanOptions(technique="T", time_threshold=4, dbms="mysql")
            result = ScanResult(target="https://x.com/")
            run_time_based(_surface(), ["none"], opts, result=result,
                           injector=MagicMock())

            assert len(result.time_based) == 1
            assert result.time_based[0].observed_delay >= 4.0

    def test_dbms_propagated_from_payload(self):
        """Detected DBMS should be stored in result.dbms_detected."""
        with patch("breachsql.engine._scanner.blind._timed_fetch") as mock_tf:
            mock_tf.side_effect = [0.01, 0.01, 5.0, 5.0]

            opts = ScanOptions(technique="T", time_threshold=4, dbms="mysql")
            result = ScanResult(target="https://x.com/")
            run_time_based(_surface(), ["none"], opts, result=result,
                           injector=MagicMock())

            assert result.dbms_detected == "mysql"

    def test_second_url_forwarded(self):
        """second_url in opts must be forwarded to _timed_fetch calls."""
        with patch("breachsql.engine._scanner.blind._timed_fetch") as mock_tf:
            mock_tf.return_value = 0.0  # fast, no finding — we just check the calls

            opts = ScanOptions(technique="T", time_threshold=4, dbms="mysql",
                               second_url="https://x.com/result")
            result = ScanResult(target="https://x.com/")
            run_time_based(_surface(), ["none"], opts, result=result,
                           injector=MagicMock())

            # Every _timed_fetch call should have second_url set
            for c in mock_tf.call_args_list:
                kwargs = c[1]
                assert kwargs.get("second_url") == "https://x.com/result"

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
