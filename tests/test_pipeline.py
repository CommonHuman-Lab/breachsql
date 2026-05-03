# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Integration-style tests for engine/_scanner/pipeline.py"""

from __future__ import annotations

from unittest.mock import MagicMock, patch, call

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

    def test_post_data_adds_surfaces(self, mock_waf):
        """POST data params should add injectable surfaces."""
        waf_result = MagicMock(detected=False, evasions=["none"])
        mock_waf.detect.return_value = waf_result

        injector = _mock_injector(params=[])  # no GET params
        opts = ScanOptions(technique="E", data="username=admin&password=test")
        result = ScanResult(target="https://x.com/login")

        with patch("breachsql.engine._scanner.pipeline.scan_param") as mock_scan:
            run("https://x.com/login", opts, injector, result)
            # Two POST params = two scan_param calls
            assert mock_scan.call_count == 2

        assert result.params_tested == 2


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


@patch("breachsql.engine._scanner.pipeline.waf_detect")
class TestPipelineSecondUrl:
    def test_second_url_forwarded_via_opts(self, mock_waf):
        """opts.second_url must reach scan_param (which reads it from opts)."""
        waf_result = MagicMock(detected=False, evasions=["none"])
        mock_waf.detect.return_value = waf_result

        injector = _mock_injector(params=["id"])
        opts = ScanOptions(technique="E", second_url="https://x.com/result",
                           data="id=1")
        result = ScanResult(target="https://x.com/inject")

        with patch("breachsql.engine._scanner.pipeline.scan_param") as mock_scan:
            run("https://x.com/inject", opts, injector, result)
            # opts (containing second_url) must be passed to scan_param
        for c in mock_scan.call_args_list:
            _, kwargs = c
            passed_opts = c[0][2] if len(c[0]) >= 3 else kwargs.get("opts")
            assert passed_opts.second_url == "https://x.com/result"


@patch("breachsql.engine._scanner.pipeline.waf_detect")
class TestPipelinePathParams:
    def test_colon_placeholder_creates_path_surface(self, mock_waf):
        """:id pattern in URL path should auto-create a PATH surface."""
        waf_result = MagicMock(detected=False, evasions=["none"])
        mock_waf.detect.return_value = waf_result

        injector = _mock_injector(params=[])  # no GET params
        opts = ScanOptions(technique="E")
        result = ScanResult(target="https://x.com/rest/track-order/:id")

        with patch("breachsql.engine._scanner.pipeline.scan_param") as mock_scan:
            run("https://x.com/rest/track-order/:id", opts, injector, result)
            assert mock_scan.call_count == 1
            surface = mock_scan.call_args[0][0]
            assert surface["method"] == "PATH"
            assert surface["single_param"] == "id"
            assert surface["path_index"] == 3  # ['', 'rest', 'track-order', ':id']

        assert result.params_tested == 1

    def test_brace_placeholder_creates_path_surface(self, mock_waf):
        """{name} pattern in URL path should auto-create a PATH surface."""
        waf_result = MagicMock(detected=False, evasions=["none"])
        mock_waf.detect.return_value = waf_result

        injector = _mock_injector(params=[])
        opts = ScanOptions(technique="E")
        result = ScanResult(target="https://x.com/users/{id}/profile")

        with patch("breachsql.engine._scanner.pipeline.scan_param") as mock_scan:
            run("https://x.com/users/{id}/profile", opts, injector, result)
            assert mock_scan.call_count == 1
            surface = mock_scan.call_args[0][0]
            assert surface["method"] == "PATH"
            assert surface["single_param"] == "id"

    def test_explicit_path_params_option(self, mock_waf):
        """--path-params names should force path surface creation."""
        waf_result = MagicMock(detected=False, evasions=["none"])
        mock_waf.detect.return_value = waf_result

        injector = _mock_injector(params=[])
        # URL has no placeholder syntax but user specified --path-params id
        opts = ScanOptions(technique="E", path_params=["id"])
        result = ScanResult(target="https://x.com/rest/track-order/123")

        with patch("breachsql.engine._scanner.pipeline.scan_param") as mock_scan:
            run("https://x.com/rest/track-order/123", opts, injector, result)
            assert mock_scan.call_count == 1
            surface = mock_scan.call_args[0][0]
            assert surface["method"] == "PATH"
            assert surface["single_param"] == "id"

    def test_no_path_placeholders_no_path_surfaces(self, mock_waf):
        """Plain URL with no placeholders and no --path-params should have 0 path surfaces."""
        waf_result = MagicMock(detected=False, evasions=["none"])
        mock_waf.detect.return_value = waf_result

        injector = _mock_injector(params=[])
        opts = ScanOptions(technique="E")
        result = ScanResult(target="https://x.com/search")

        with patch("breachsql.engine._scanner.pipeline.scan_param") as mock_scan:
            run("https://x.com/search", opts, injector, result)
            assert mock_scan.call_count == 0
