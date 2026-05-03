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


class TestTimeBlindPayloads:
    """Verify per-DBMS time-blind extraction payload syntax."""

    def _collect_time_payloads(self, dbms: str) -> list:
        """Run extract_value in time mode and collect all _timed_fetch payloads."""
        seen = []

        def _timed(injector, url, method, params, param, value,
                   second_url="", json_body=False, path_index=0):
            seen.append(value)
            return 0.0  # always fast → extraction terminates quickly

        with patch("breachsql.engine._scanner.extract._timed_fetch", side_effect=_timed):
            opts = ScanOptions(dbms=dbms, time_threshold=4)
            extract_value(
                expr="VERSION()",
                surface=_surface(),
                evasions=["none"],
                opts=opts,
                injector=MagicMock(),
                baseline="",
                mode="time",
            )
        return seen

    def test_mysql_uses_if_sleep(self):
        payloads = self._collect_time_payloads("mysql")
        assert any("IF(" in p and "SLEEP(" in p for p in payloads)

    def test_postgres_uses_pg_sleep(self):
        payloads = self._collect_time_payloads("postgres")
        assert any("pg_sleep(" in p for p in payloads)

    def test_sqlite_uses_randomblob(self):
        payloads = self._collect_time_payloads("sqlite")
        assert any("randomblob(" in p.lower() or "WITH RECURSIVE" in p for p in payloads)

    def test_mssql_uses_stacked_waitfor(self):
        """MSSQL time-blind must use stacked IF ... WAITFOR DELAY, not a SELECT subquery."""
        payloads = self._collect_time_payloads("mssql")
        for p in payloads:
            # Must be stacked (starts with ';') and use IF + WAITFOR
            assert "SELECT WAITFOR" not in p, (
                f"MSSQL payload must not use SELECT WAITFOR subquery: {p}"
            )
        assert any("WAITFOR DELAY" in p and p.startswith("'") and "IF " in p
                   for p in payloads)
