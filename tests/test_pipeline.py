# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Integration-style tests for engine/_scanner/pipeline.py"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from breachsql.engine._scanner.pipeline import run
from breachsql.engine._scanner.options import ScanOptions
from breachsql.engine.reporter import ScanResult


def _mock_injector(params=None, body="<html>OK</html>"):
    injector = MagicMock()
    r = MagicMock()
    r.text = body
    r.status_code = 200
    r.headers = {}
    injector.get.return_value = r
    injector.inject_get.return_value = r
    injector.post.return_value = r
    injector.get_params.return_value = ["q"] if params is None else params
    injector.request_count = 0
    return injector


@patch("breachsql.engine._scanner.pipeline.waf_detect")
class TestPipelineWafStage:
    def test_waf_detection_called(self, mock_waf):
        waf_result = MagicMock()
        waf_result.detected = False
        waf_result.evasions = ["none"]
        mock_waf.detect.return_value = waf_result

        injector = _mock_injector()
        opts = ScanOptions(technique="E")
        result = ScanResult(target="https://x.com/?q=1")

        run("https://x.com/?q=1", opts, injector, result)

        mock_waf.detect.assert_called_once()

    def test_waf_name_stored_in_result(self, mock_waf):
        waf_result = MagicMock()
        waf_result.detected = True
        waf_result.name = "Cloudflare"
        waf_result.confidence = "high"
        waf_result.evasions = ["sql_comment"]
        mock_waf.detect.return_value = waf_result

        injector = _mock_injector()
        opts = ScanOptions(technique="E")
        result = ScanResult(target="https://x.com/?q=1")

        run("https://x.com/?q=1", opts, injector, result)

        assert result.waf_detected == "Cloudflare"
        assert result.evasion_applied == "sql_comment"


@patch("breachsql.engine._scanner.pipeline.waf_detect")
class TestPipelineSurfaces:
    def test_params_tested_set(self, mock_waf):
        waf_result = MagicMock(detected=False, evasions=["none"])
        mock_waf.detect.return_value = waf_result

        injector = _mock_injector(params=["id", "name"])
        opts = ScanOptions(technique="E")
        result = ScanResult(target="https://x.com/?id=1&name=foo")

        run("https://x.com/?id=1&name=foo", opts, injector, result)

        assert result.params_tested == 2

    def test_no_params_no_surfaces(self, mock_waf):
        waf_result = MagicMock(detected=False, evasions=["none"])
        mock_waf.detect.return_value = waf_result

        injector = _mock_injector(params=[])
        opts = ScanOptions(technique="E")
        result = ScanResult(target="https://x.com/")

        run("https://x.com/", opts, injector, result)

        assert result.params_tested == 0


@patch("breachsql.engine._scanner.pipeline.waf_detect")
@patch("breachsql.engine._scanner.pipeline.scan_param")
class TestPipelineTechniqueGating:
    def test_active_not_called_when_no_active_techniques(self, mock_test, mock_waf):
        waf_result = MagicMock(detected=False, evasions=["none"])
        mock_waf.detect.return_value = waf_result

        injector = _mock_injector()
        # Only time-based — scan_param (error/bool/union) should not be called
        opts = ScanOptions(technique="T")
        result = ScanResult(target="https://x.com/?q=1")

        with patch("breachsql.engine._scanner.pipeline.run_time_based") as mock_time:
            run("https://x.com/?q=1", opts, injector, result)
            mock_test.assert_not_called()
            mock_time.assert_called()

    def test_oob_not_called_without_callback(self, mock_test, mock_waf):
        waf_result = MagicMock(detected=False, evasions=["none"])
        mock_waf.detect.return_value = waf_result

        injector = _mock_injector()
        opts = ScanOptions(technique="O", oob_callback="")
        result = ScanResult(target="https://x.com/?q=1")

        with patch("breachsql.engine._scanner.pipeline.run_oob") as mock_oob:
            run("https://x.com/?q=1", opts, injector, result)
            mock_oob.assert_not_called()
