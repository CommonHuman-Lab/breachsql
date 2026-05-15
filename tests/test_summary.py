# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for breachsql/_cli/summary.py."""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from unittest.mock import patch

import pytest

from breachsql._cli.summary import _proof_url, print_summary
from breachsql.engine.reporter import (
    BooleanFinding,
    ErrorBasedFinding,
    ExtractionFinding,
    OOBFinding,
    ScanResult,
    StackedFinding,
    TimeFinding,
    UnionFinding,
)


# ---------------------------------------------------------------------------
# _proof_url
# ---------------------------------------------------------------------------

class TestProofUrl:
    def test_injects_payload_into_param(self):
        url = _proof_url("https://x.com/search?q=test", "q", "' OR 1=1-- -")
        assert "q=" in url
        assert "OR" in url or "%27" in url or "27" in url

    def test_param_not_in_qs_uses_default(self):
        url = _proof_url("https://x.com/search?other=test", "q", "'")
        assert "q=" in url

    def test_non_standard_url_still_returns_string(self):
        # urlparse is very permissive — it won't raise, so _proof_url always returns a string
        result = _proof_url("not a url", "q", "'")
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# print_summary helpers
# ---------------------------------------------------------------------------

def _capture(result) -> str:
    buf = io.StringIO()
    with redirect_stdout(buf):
        print_summary(result)
    return buf.getvalue()


def _empty_result(**kwargs) -> ScanResult:
    r = ScanResult(target="https://x.com/")
    r.duration_s = 1.23
    r.requests_sent = 42
    r.crawled_urls = 3
    r.params_tested = 5
    r.waf_detected = kwargs.get("waf_detected")
    r.evasion_applied = kwargs.get("evasion_applied")
    r.dbms_detected = kwargs.get("dbms_detected")
    return r


# ---------------------------------------------------------------------------
# print_summary — header / metadata
# ---------------------------------------------------------------------------

class TestPrintSummaryHeader:
    def test_target_shown(self):
        out = _capture(_empty_result())
        assert "https://x.com/" in out

    def test_duration_shown(self):
        out = _capture(_empty_result())
        assert "1.23" in out

    def test_requests_sent_shown(self):
        out = _capture(_empty_result())
        assert "42" in out

    def test_no_findings_message(self):
        out = _capture(_empty_result())
        assert "No findings" in out

    def test_waf_shown_when_detected(self):
        out = _capture(_empty_result(waf_detected="Cloudflare"))
        assert "Cloudflare" in out

    def test_evasion_shown_when_applied(self):
        out = _capture(_empty_result(evasion_applied="space_comment"))
        assert "space_comment" in out

    def test_dbms_shown_when_detected(self):
        out = _capture(_empty_result(dbms_detected="mysql"))
        assert "mysql" in out

    def test_none_fields_show_fallback_labels(self):
        out = _capture(_empty_result())
        assert "None" in out or "Unknown" in out


# ---------------------------------------------------------------------------
# print_summary — error-based findings
# ---------------------------------------------------------------------------

class TestPrintSummaryErrorBased:
    def test_error_based_finding_shown(self):
        r = _empty_result()
        r.error_based.append(ErrorBasedFinding(
            url="https://x.com/search?q=1",
            parameter="q",
            method="GET",
            payload="'",
            dbms="mysql",
            evidence="You have an error in your SQL syntax",
        ))
        out = _capture(r)
        assert "ERROR-BASED" in out
        assert "q" in out
        assert "mysql" in out
        assert "You have an error" in out

    def test_error_based_proof_url_shown_for_get(self):
        r = _empty_result()
        r.error_based.append(ErrorBasedFinding(
            url="https://x.com/search?q=1",
            parameter="q",
            method="GET",
            payload="'",
            dbms="mysql",
        ))
        out = _capture(r)
        assert "Proof" in out

    def test_error_based_no_proof_for_post(self):
        r = _empty_result()
        r.error_based.append(ErrorBasedFinding(
            url="https://x.com/login",
            parameter="email",
            method="POST",
            payload="'",
            dbms="mysql",
        ))
        out = _capture(r)
        assert "Proof" not in out


# ---------------------------------------------------------------------------
# print_summary — boolean findings
# ---------------------------------------------------------------------------

class TestPrintSummaryBoolean:
    def test_confirmed_boolean_shown(self):
        r = _empty_result()
        r.boolean_based.append(BooleanFinding(
            url="https://x.com/login",
            parameter="email",
            method="POST",
            payload_true="' OR 1=1-- -",
            payload_false="' OR 1=2-- -",
            diff_score=1.0,
            confirmed=True,
        ))
        out = _capture(r)
        assert "Boolean" in out or "boolean" in out.lower()
        assert "email" in out
        assert "1.00" in out

    def test_likely_boolean_shown_differently(self):
        r = _empty_result()
        r.boolean_based.append(BooleanFinding(
            url="https://x.com/search?q=1",
            parameter="q",
            method="GET",
            payload_true="' OR 1=1-- -",
            payload_false="' OR 1=2-- -",
            diff_score=0.35,
            confirmed=False,
        ))
        out = _capture(r)
        assert "LIKELY" in out or "Boolean" in out.lower() or "boolean" in out

    def test_boolean_proof_shown_for_get(self):
        r = _empty_result()
        r.boolean_based.append(BooleanFinding(
            url="https://x.com/search?q=1",
            parameter="q",
            method="GET",
            payload_true="' OR 1=1-- -",
            payload_false="' OR 1=2-- -",
            diff_score=1.0,
            confirmed=True,
        ))
        out = _capture(r)
        assert "Proof" in out


# ---------------------------------------------------------------------------
# print_summary — time-based findings
# ---------------------------------------------------------------------------

class TestPrintSummaryTimeBased:
    def test_time_based_finding_shown(self):
        r = _empty_result()
        r.time_based.append(TimeFinding(
            url="https://x.com/search?q=1",
            parameter="q",
            method="GET",
            payload="' AND SLEEP(5)-- -",
            dbms="mysql",
            observed_delay=5.3,
            threshold=4,
        ))
        out = _capture(r)
        assert "TIME" in out
        assert "5.30" in out
        assert "4" in out


# ---------------------------------------------------------------------------
# print_summary — union findings
# ---------------------------------------------------------------------------

class TestPrintSummaryUnion:
    def test_union_finding_shown(self):
        r = _empty_result()
        r.union_based.append(UnionFinding(
            url="https://x.com/search?q=1",
            parameter="q",
            method="GET",
            payload="')) UNION SELECT 'BreachSQL_x',2-- -",
            column_count=2,
            extracted="BreachSQL_x",
        ))
        out = _capture(r)
        assert "UNION" in out
        assert "2" in out  # column count

    def test_union_extracted_snippet_shown(self):
        r = _empty_result()
        r.union_based.append(UnionFinding(
            url="https://x.com/search?q=1",
            parameter="q",
            method="GET",
            payload="')) UNION SELECT 'BreachSQL_x',2-- -",
            column_count=2,
            extracted="some extracted data",
        ))
        out = _capture(r)
        assert "some extracted data" in out


# ---------------------------------------------------------------------------
# print_summary — OOB findings
# ---------------------------------------------------------------------------

class TestPrintSummaryOOB:
    def test_oob_finding_shown(self):
        r = _empty_result()
        r.oob.append(OOBFinding(
            url="https://x.com/search?q=1",
            parameter="q",
            method="GET",
            payload="'; LOAD_FILE(concat(0x5c5c,callback.com,0x5c))-- -",
            callback_url="http://callback.example.com",
        ))
        out = _capture(r)
        assert "OOB" in out
        assert "callback.example.com" in out


# ---------------------------------------------------------------------------
# print_summary — stacked findings
# ---------------------------------------------------------------------------

class TestPrintSummaryStacked:
    def test_stacked_finding_shown(self):
        r = _empty_result()
        r.stacked.append(StackedFinding(
            url="https://x.com/search?q=1",
            parameter="q",
            method="GET",
            payload="'; SELECT SLEEP(1)-- -",
            dbms="mysql",
            evidence="delay observed",
        ))
        out = _capture(r)
        assert "STACKED" in out
        assert "delay observed" in out


# ---------------------------------------------------------------------------
# print_summary — extracted data section
# ---------------------------------------------------------------------------

class TestPrintSummaryExtracted:
    def test_extracted_union_shown(self):
        r = _empty_result()
        r.union_based.append(UnionFinding(
            url="https://x.com/search?q=1",
            parameter="q", method="GET",
            payload="')) UNION SELECT 'BreachSQL_x',2-- -",
            column_count=2,
        ))
        r.extracted.append(ExtractionFinding(
            url="https://x.com/search?q=1",
            parameter="q",
            method="GET",
            expr="VERSION()",
            value="8.0.32",
            mode="union",
        ))
        out = _capture(r)
        assert "EXTRACTED" in out
        assert "8.0.32" in out
        assert "union" in out

    def test_extracted_boolean_blind_label(self):
        r = _empty_result()
        r.boolean_based.append(BooleanFinding(
            url="https://x.com/search?q=1",
            parameter="q", method="GET",
            payload_true="' OR 1=1-- -",
            payload_false="' OR 1=2-- -",
            diff_score=1.0, confirmed=True,
        ))
        r.extracted.append(ExtractionFinding(
            url="https://x.com/search?q=1",
            parameter="q",
            method="GET",
            expr="USER()",
            value="root@localhost",
            mode="boolean",
        ))
        out = _capture(r)
        assert "boolean-blind" in out

    def test_extracted_time_blind_label(self):
        r = _empty_result()
        r.time_based.append(TimeFinding(
            url="https://x.com/search?q=1",
            parameter="q", method="GET",
            payload="' AND SLEEP(5)-- -",
            dbms="mysql", observed_delay=5.0, threshold=4,
        ))
        r.extracted.append(ExtractionFinding(
            url="https://x.com/search?q=1",
            parameter="q",
            method="GET",
            expr="DATABASE()",
            value="shopdb",
            mode="time",
        ))
        out = _capture(r)
        assert "time-blind" in out


# ---------------------------------------------------------------------------
# print_summary — errors section
# ---------------------------------------------------------------------------

class TestPrintSummaryErrors:
    def test_errors_shown(self):
        r = _empty_result()
        r.errors = ["Connection timeout on https://x.com/"]
        out = _capture(r)
        assert "Connection timeout" in out

    def test_multiple_errors_all_shown(self):
        r = _empty_result()
        r.errors = ["Error A", "Error B"]
        out = _capture(r)
        assert "Error A" in out
        assert "Error B" in out
