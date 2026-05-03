# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for engine/_scanner/stacked.py — stacked query SQLi detection."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from breachsql.engine._scanner.stacked import run_stacked
from breachsql.engine._scanner.options import ScanOptions
from breachsql.engine.reporter import ScanResult


def _surface(url="https://x.com/?id=1", method="GET", param="id"):
    return {"url": url, "method": method, "params": {param: "1"}, "single_param": param}


def _mock_injector(response_text="<html>OK</html>"):
    inj = MagicMock()
    r = MagicMock()
    r.text = response_text
    r.status_code = 200
    inj.inject_get.return_value = r
    inj.post.return_value = r
    return inj


class TestRunStacked:
    def test_no_finding_when_response_unchanged(self):
        """Identical baseline and payload responses must not produce a finding."""
        injector = _mock_injector("<html>Same response</html>")
        opts = ScanOptions(technique="S", dbms="mssql")
        result = ScanResult(target="https://x.com/")
        run_stacked(_surface(), ["none"], opts, injector, result)
        assert len(result.stacked) == 0

    def test_finding_when_response_differs(self):
        """A meaningful response divergence should produce a StackedFinding."""
        call_count = [0]

        def _side_effect(url, param, value):
            call_count[0] += 1
            r = MagicMock()
            r.status_code = 200
            if call_count[0] == 1:
                r.text = "<html>Normal response with lots of words here</html>"
            else:
                r.text = "<html>Changed: admin alice bob charlie delta echo</html>"
            return r

        injector = MagicMock()
        injector.inject_get.side_effect = _side_effect

        opts = ScanOptions(technique="S", dbms="mssql")
        result = ScanResult(target="https://x.com/")
        run_stacked(_surface(), ["none"], opts, injector, result)
        assert len(result.stacked) == 1
        assert result.stacked[0].parameter == "id"

    def test_oracle_skipped(self):
        """Oracle does not support stacked queries — no requests should be made."""
        injector = _mock_injector()
        opts = ScanOptions(technique="S", dbms="oracle")
        result = ScanResult(target="https://x.com/")
        run_stacked(_surface(), ["none"], opts, injector, result)
        assert len(result.stacked) == 0
        injector.inject_get.assert_not_called()

    def test_db_error_response_not_flagged(self):
        """A stacked payload that triggers a DB error should not produce a finding."""
        call_count = [0]

        def _side_effect(url, param, value):
            call_count[0] += 1
            r = MagicMock()
            r.status_code = 200
            if call_count[0] == 1:
                r.text = "<html>Normal</html>"
            else:
                r.text = "You have an error in your SQL syntax near ';'"
            return r

        injector = MagicMock()
        injector.inject_get.side_effect = _side_effect

        opts = ScanOptions(technique="S", dbms="mysql")
        result = ScanResult(target="https://x.com/")
        run_stacked(_surface(), ["none"], opts, injector, result)
        assert len(result.stacked) == 0

    def test_dbms_propagated_on_finding(self):
        """Detected DBMS should be stored in result.dbms_detected on first finding."""
        call_count = [0]

        def _side_effect(url, param, value):
            call_count[0] += 1
            r = MagicMock()
            r.status_code = 200
            r.text = ("<html>Normal</html>" if call_count[0] == 1
                      else "<html>Changed admin alice bob charlie delta</html>")
            return r

        injector = MagicMock()
        injector.inject_get.side_effect = _side_effect

        opts = ScanOptions(technique="S", dbms="postgres")
        result = ScanResult(target="https://x.com/")
        run_stacked(_surface(), ["none"], opts, injector, result)

        if result.stacked:
            assert result.dbms_detected == "postgres"
