# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for engine/_scanner/extract.py — blind data extraction engine."""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

import pytest

from breachsql.engine._scanner.extract import extract_value
from breachsql.engine._scanner.options import ScanOptions


def _surface(url="https://x.com/?id=1", method="GET", param="id"):
    return {"url": url, "method": method, "params": {param: "1"}, "single_param": param}


class TestExtractValue:
    def test_extracts_known_string_boolean(self):
        """Binary-search extraction must recover a known string character by character."""
        target = "abc"

        def _fetch_side(injector, url, method, params, param, value,
                        second_url="", json_body=False, path_index=0):
            if value is None:
                return "<html>User exists</html>"
            m = re.search(r"ASCII\(SUBSTRING\(\((.+?)\),(\d+),1\)\)>(\d+)", value)
            if not m:
                return "<html>User does not exist</html>"
            pos = int(m.group(2))
            threshold = int(m.group(3))
            actual_ord = ord(target[pos - 1]) if pos <= len(target) else 0
            if actual_ord > threshold:
                return "<html>User exists</html>"
            return "<html>User does not exist</html>"

        with patch("breachsql.engine._scanner.extract._fetch", side_effect=_fetch_side):
            opts = ScanOptions(dbms="mysql")
            extracted = extract_value(
                expr="SELECT 'abc'",
                surface=_surface(),
                evasions=["none"],
                opts=opts,
                injector=MagicMock(),
                baseline="<html>User exists</html>",
                mode="boolean",
            )
        assert extracted.rstrip() == "abc"

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
