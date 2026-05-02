# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for engine/_scanner/options.py — ScanOptions validation."""

from __future__ import annotations

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
