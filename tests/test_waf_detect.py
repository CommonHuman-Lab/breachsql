# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Smoke tests for engine/http/waf_detect.py — confirms the breachsql adapter
correctly wraps commonhuman_payloads.waf.detect() via injector.get.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from breachsql.engine.http.waf_detect import (
    detect,
    WafResult,
    EVASION_NONE,
    EVASION_SQL_COMMENT,
)


def _mock_injector(status: int = 200, headers: dict | None = None, body: str = "<html>OK</html>"):
    injector = MagicMock()
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    resp.text = body
    injector.get.return_value = resp
    return injector


class TestWafDetectAdapter:
    """Breachsql wraps detect() with injector.get, SQLi probe, check_reflection=False."""

    URL = "https://example.com/?q=1"

    def test_clean_200_no_waf(self):
        injector = _mock_injector(200, body="<html>OK normal response</html>")
        result = detect(injector, self.URL)
        assert isinstance(result, WafResult)
        assert result.detected is False
        assert result.evasions == [EVASION_NONE]

    def test_cloudflare_detected_through_adapter(self):
        injector = _mock_injector(
            status=403,
            headers={"cf-ray": "abc123", "server": "cloudflare"},
            body="Attention Required! | Cloudflare",
        )
        result = detect(injector, self.URL)
        assert result.detected is True
        assert result.name == "Cloudflare"
        assert EVASION_SQL_COMMENT in result.evasions

    def test_exception_returns_no_waf(self):
        injector = MagicMock()
        injector.get.side_effect = Exception("connection refused")
        result = detect(injector, self.URL)
        assert result.detected is False
