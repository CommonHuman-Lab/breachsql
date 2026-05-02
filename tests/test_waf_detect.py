# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for engine/http/waf_detect.py — WAF fingerprinting."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from breachsql.engine.http.waf_detect import (
    detect,
    WafResult,
    EVASION_NONE,
    EVASION_SQL_COMMENT,
    EVASION_SQL_CASE,
)


def _mock_injector(status: int = 200, headers: dict | None = None, body: str = "<html>OK</html>"):
    injector = MagicMock()
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    resp.text = body
    injector.get.return_value = resp
    return injector


class TestWafDetectNoWaf:
    def test_clean_200_no_waf(self):
        injector = _mock_injector(200, body="<html>OK normal response</html>")
        result = detect(injector, "https://example.com/?q=1")
        assert result.detected is False
        assert result.confidence == "none"
        assert result.evasions == [EVASION_NONE]

    def test_injector_exception_returns_no_waf(self):
        injector = MagicMock()
        injector.get.side_effect = Exception("connection refused")
        result = detect(injector, "https://example.com/?q=1")
        assert result.detected is False


class TestWafDetectCloudflare:
    def test_cloudflare_header(self):
        injector = _mock_injector(
            status=403,
            headers={"cf-ray": "abc123", "server": "cloudflare"},
            body="Attention Required! | Cloudflare",
        )
        result = detect(injector, "https://example.com/?q=1")
        assert result.detected is True
        assert result.name == "Cloudflare"
        assert result.confidence in ("high", "medium")
        assert EVASION_SQL_COMMENT in result.evasions

    def test_cloudflare_body_only(self):
        injector = _mock_injector(
            status=403,
            headers={},
            body="Error 1020: Ray ID cf-ray — Access denied | Cloudflare",
        )
        result = detect(injector, "https://example.com/?q=1")
        # May detect as Cloudflare or Generic WAF depending on score
        assert result.detected is True


class TestWafDetectModSecurity:
    def test_modsecurity_406(self):
        injector = _mock_injector(
            status=406,
            headers={"server": "Apache/mod_security"},
            body="406 Not Acceptable — ModSecurity",
        )
        result = detect(injector, "https://example.com/?q=1")
        assert result.detected is True
        assert result.name == "ModSecurity"


class TestWafDetectGeneric:
    def test_403_with_access_denied(self):
        injector = _mock_injector(
            status=403,
            headers={},
            body="<h1>Access Denied</h1><p>Your request was blocked.</p>",
        )
        result = detect(injector, "https://example.com/?q=1")
        assert result.detected is True
        # "Access Denied" matches Akamai body clue — acceptable for either Akamai or Generic WAF
        assert result.name in ("Akamai", "Generic WAF")
        assert result.confidence in ("low", "medium")

    def test_503_triggers_detection(self):
        injector = _mock_injector(status=503, body="Service Unavailable")
        result = detect(injector, "https://example.com/?q=1")
        assert result.detected is True


class TestWafDetectEvasions:
    def test_evasions_list_non_empty_when_detected(self):
        injector = _mock_injector(
            status=403,
            headers={"cf-ray": "x", "server": "cloudflare"},
            body="Cloudflare",
        )
        result = detect(injector, "https://example.com/?q=1")
        assert len(result.evasions) > 0

    def test_no_waf_evasions_is_none_strategy(self):
        injector = _mock_injector(200)
        result = detect(injector, "https://example.com/?q=1")
        assert result.evasions == [EVASION_NONE]
