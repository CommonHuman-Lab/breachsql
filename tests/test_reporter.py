# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for reporter.py — ScanResult dataclasses and serialisation."""

from __future__ import annotations

import time

import pytest

from breachsql.engine.reporter import (
    ScanResult,
    ErrorBasedFinding,
    BooleanFinding,
    TimeFinding,
    UnionFinding,
    OOBFinding,
    StackedFinding,
    FindingType,
    _FINDING_LISTS,
)


def _make_result() -> ScanResult:
    return ScanResult(target="https://example.com/search?q=1")


class TestScanResultBasics:
    def test_initial_state(self):
        r = _make_result()
        assert r.total_findings == 0
        assert r.errors == []
        assert r.log == []
        assert r.waf_detected is None
        assert r.dbms_detected is None

    def test_finish_sets_duration(self):
        r = _make_result()
        time.sleep(0.01)
        r.finish()
        assert r.duration_s >= 0.0
        assert r.finished_at > r.started_at

    def test_success_no_errors(self):
        r = _make_result()
        assert r.success is True  # no errors

    def test_success_with_errors_but_findings(self):
        r = _make_result()
        r.append_error("something went wrong")
        r.append_error_based(ErrorBasedFinding(
            url="https://example.com/search?q=1",
            parameter="q", method="GET", payload="'", dbms="mysql",
        ))
        assert r.success is True  # findings override errors

    def test_success_false_only_errors(self):
        r = _make_result()
        r.append_error("oops")
        assert r.success is False


class TestFindingAppend:
    def test_append_error_based(self):
        r = _make_result()
        f = ErrorBasedFinding(
            url="https://x.com/", parameter="id", method="GET",
            payload="'", dbms="mysql", evidence="You have an error",
        )
        r.append_error_based(f)
        assert len(r.error_based) == 1
        assert r.total_findings == 1

    def test_append_boolean(self):
        r = _make_result()
        f = BooleanFinding(
            url="https://x.com/", parameter="id", method="GET",
            payload_true="' AND 1=1--", payload_false="' AND 1=2--",
            diff_score=0.35, confirmed=True,
        )
        r.append_boolean(f)
        assert len(r.boolean_based) == 1
        assert r.total_findings == 1

    def test_append_time(self):
        r = _make_result()
        f = TimeFinding(
            url="https://x.com/", parameter="id", method="GET",
            payload="' AND SLEEP(4)--", dbms="mysql",
            observed_delay=4.2, threshold=4,
        )
        r.append_time(f)
        assert len(r.time_based) == 1

    def test_append_union(self):
        r = _make_result()
        f = UnionFinding(
            url="https://x.com/", parameter="id", method="GET",
            payload="' UNION SELECT NULL,NULL--", column_count=2,
            extracted="BreachSQL_abc123",
        )
        r.append_union(f)
        assert len(r.union_based) == 1

    def test_append_oob(self):
        r = _make_result()
        f = OOBFinding(
            url="https://x.com/", parameter="id", method="GET",
            payload="'; EXEC xp_dirtree '//cb.io/a'--",
            callback_url="https://cb.io",
        )
        r.append_oob(f)
        assert len(r.oob) == 1

    def test_total_findings_sums_all_lists(self):
        r = _make_result()
        r.append_error_based(ErrorBasedFinding("u", "p", "GET", "pl", "mysql"))
        r.append_boolean(BooleanFinding("u", "p", "GET", "t", "f", 0.3, True))
        r.append_time(TimeFinding("u", "p", "GET", "pl", "mysql", 5.0, 4))
        r.append_union(UnionFinding("u", "p", "GET", "pl", 2))
        r.append_oob(OOBFinding("u", "p", "GET", "pl", "https://cb.io"))
        assert r.total_findings == 5


class TestToDict:
    def test_empty_result(self):
        r = _make_result()
        r.finish()
        d = r.to_dict()
        assert d["total_findings"] == 0
        assert d["findings"] == []
        assert d["target"] == "https://example.com/search?q=1"
        assert "duration_s" in d
        assert "waf_detected" in d
        assert "dbms_detected" in d

    def test_finding_type_tag(self):
        r = _make_result()
        r.append_error_based(ErrorBasedFinding("u", "p", "GET", "'", "mysql", "err"))
        d = r.to_dict()
        assert d["findings"][0]["type"] == FindingType.ERROR_BASED.value

    def test_all_finding_types_serialise(self):
        r = _make_result()
        r.append_error_based(ErrorBasedFinding("u", "p", "GET", "'", "mysql"))
        r.append_boolean(BooleanFinding("u", "p", "GET", "t", "f", 0.3, True))
        r.append_time(TimeFinding("u", "p", "GET", "sl", "mysql", 5.0, 4))
        r.append_union(UnionFinding("u", "p", "GET", "un", 2))
        r.append_oob(OOBFinding("u", "p", "GET", "oob", "https://cb.io"))
        d = r.to_dict()
        types = {f["type"] for f in d["findings"]}
        assert types == {
            "error_based_sqli", "boolean_based_sqli",
            "time_based_sqli", "union_based_sqli", "oob_sqli",
        }

    def test_finding_lists_registry_completeness(self):
        """Every attribute in _FINDING_LISTS must exist on ScanResult."""
        r = _make_result()
        for attr, _ in _FINDING_LISTS:
            assert hasattr(r, attr), f"ScanResult missing attribute: {attr}"


class TestStackedFinding:
    def test_append_stacked(self):
        r = _make_result()
        r.append_stacked(StackedFinding(
            url="https://x.com/?id=1", parameter="id", method="GET",
            payload="'; SELECT 1-- -", dbms="mssql", evidence="<html>Changed</html>",
        ))
        assert len(r.stacked) == 1
        assert r.total_findings == 1

    def test_stacked_serialised_in_to_dict(self):
        r = _make_result()
        r.append_stacked(StackedFinding(
            url="https://x.com/", parameter="id", method="GET",
            payload="'; SELECT 1-- -", dbms="mssql", evidence="",
        ))
        stacked = [f for f in r.to_dict()["findings"] if f["type"] == "stacked_sqli"]
        assert len(stacked) == 1

    def test_finding_type_value(self):
        assert FindingType.STACKED.value == "stacked_sqli"
