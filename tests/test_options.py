# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for engine/_scanner/options.py — ScanOptions validation."""

from __future__ import annotations

import warnings

import pytest

from breachsql.engine._scanner.options import ScanOptions


class TestScanOptionsDefaults:
    def test_default_technique(self):
        opts = ScanOptions()
        assert opts.technique == "EBTUO"

    def test_default_dbms(self):
        opts = ScanOptions()
        assert opts.dbms == "auto"

    def test_default_risk(self):
        opts = ScanOptions()
        assert opts.risk == 1

    def test_default_time_threshold(self):
        opts = ScanOptions()
        assert opts.time_threshold == 4

    def test_default_second_url(self):
        opts = ScanOptions()
        assert opts.second_url == ""

    def test_default_max_union_cols(self):
        opts = ScanOptions()
        assert opts.max_union_cols == 20


class TestScanOptionsClamping:
    def test_threads_clamped_low(self):
        opts = ScanOptions(threads=0)
        assert opts.threads == 1

    def test_threads_clamped_high(self):
        opts = ScanOptions(threads=99)
        assert opts.threads == 20

    def test_timeout_clamped_low(self):
        opts = ScanOptions(timeout=1)
        assert opts.timeout == 5

    def test_timeout_clamped_high(self):
        opts = ScanOptions(timeout=999)
        assert opts.timeout == 120

    def test_level_clamped(self):
        opts = ScanOptions(level=0)
        assert opts.level == 1
        opts2 = ScanOptions(level=10)
        assert opts2.level == 3

    def test_risk_clamped(self):
        opts = ScanOptions(risk=0)
        assert opts.risk == 1
        opts2 = ScanOptions(risk=9)
        assert opts2.risk == 3

    def test_time_threshold_clamped(self):
        opts = ScanOptions(time_threshold=0)
        assert opts.time_threshold == 1

    def test_delay_no_negative(self):
        opts = ScanOptions(delay=-1.0)
        assert opts.delay == 0.0

    def test_max_union_cols_clamped_low(self):
        opts = ScanOptions(max_union_cols=0)
        assert opts.max_union_cols == 1

    def test_max_union_cols_clamped_high(self):
        opts = ScanOptions(max_union_cols=999)
        assert opts.max_union_cols == 100


class TestTechniqueProperties:
    def test_all_enabled(self):
        opts = ScanOptions(technique="EBTUO")
        assert opts.use_error is True
        assert opts.use_boolean is True
        assert opts.use_time is True
        assert opts.use_union is True

    def test_oob_requires_callback(self):
        opts = ScanOptions(technique="O", oob_callback="")
        assert opts.use_oob is False

    def test_oob_enabled_with_callback(self):
        opts = ScanOptions(technique="O", oob_callback="http://cb.io")
        assert opts.use_oob is True

    def test_error_only(self):
        opts = ScanOptions(technique="E")
        assert opts.use_error is True
        assert opts.use_boolean is False
        assert opts.use_time is False
        assert opts.use_union is False

    def test_case_insensitive_technique(self):
        opts = ScanOptions(technique="ebt")
        assert opts.use_error is True
        assert opts.use_boolean is True
        assert opts.use_time is True

    def test_invalid_technique_chars_warn_and_strip(self):
        """Unknown technique letters should produce a UserWarning and be stripped."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            opts = ScanOptions(technique="EXZ")
        assert len(w) == 1
        assert issubclass(w[0].category, UserWarning)
        assert "X" in str(w[0].message) or "Z" in str(w[0].message)
        # Only valid letters survive
        assert opts.technique == "E"
        assert opts.use_boolean is False

    def test_entirely_invalid_technique_results_in_empty(self):
        """Entirely invalid technique should produce empty technique string."""
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            opts = ScanOptions(technique="XYZ")
        assert opts.technique == ""
        assert opts.use_error is False


class TestDbmsNormalisation:
    def test_dbms_lowercased(self):
        opts = ScanOptions(dbms="MySQL")
        assert opts.dbms == "mysql"

    def test_dbms_stripped(self):
        opts = ScanOptions(dbms="  MYSQL  ")
        assert opts.dbms == "mysql"


class TestSecondUrl:
    def test_second_url_stored(self):
        opts = ScanOptions(second_url="https://x.com/result")
        assert opts.second_url == "https://x.com/result"

    def test_second_url_stripped(self):
        opts = ScanOptions(second_url="  https://x.com/result  ")
        assert opts.second_url == "https://x.com/result"
