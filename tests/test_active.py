# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Tests for engine/_scanner/active.py — error-based, boolean, union detection."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from breachsql.engine._scanner.active import (
    scan_param,
    _detect_db_error,
    _diff_score,
    _extract_marker,
    _has_stable_boolean_signal,
    _len_ratio,
    _fetch,
    _find_column_count,
    strip_status_sentinel,
)
from breachsql.engine._scanner.options import ScanOptions
from breachsql.engine.reporter import ScanResult


def _mock_injector(responses: dict[str, str] | None = None):
    """Build a minimal mock Injector that returns canned responses."""
    injector = MagicMock()
    responses = responses or {}

    def _get_resp(text: str, status: int = 200):
        r = MagicMock()
        r.text = text
        r.status_code = status
        return r

    def _inject_get(url, param, value):
        # The scanner now appends payload to the original value ("1" + payload).
        # Support both the full appended value and the raw payload for lookups.
        key_full    = value.strip()[:40]
        # Strip the "1" prefix if present (original param value in test surface)
        key_payload = value.lstrip("1").strip()[:40]
        text = responses.get(key_full) or responses.get(key_payload, "<html>OK</html>")
        return _get_resp(text)

    def _post(url, data=None):
        val = (data or {}).get(list((data or {}).keys())[0] if data else "", "")
        key_full    = str(val).strip()[:40]
        key_payload = str(val).lstrip("1").strip()[:40]
        text = responses.get(key_full) or responses.get(key_payload, "<html>OK</html>")
        return _get_resp(text)

    injector.inject_get.side_effect = _inject_get
    injector.post.side_effect = _post
    injector.get_params.return_value = ["q"]
    injector.request_count = 0
    return injector


def _surface(url="https://x.com/?q=1", method="GET", param="q"):
    return {"url": url, "method": method, "params": {param: "1"}, "single_param": param}


class TestDetectDbError:
    def test_mysql_error(self):
        dbms, evidence = _detect_db_error(
            "You have an error in your SQL syntax near '1'"
        )
        assert dbms == "mysql"
        assert evidence != ""

    def test_mssql_error(self):
        dbms, evidence = _detect_db_error(
            "Incorrect syntax near the keyword 'AND'. Microsoft SQL Server"
        )
        assert dbms == "mssql"

    def test_postgres_error(self):
        dbms, evidence = _detect_db_error(
            "ERROR: invalid input syntax for type integer"
        )
        assert dbms == "postgres"

    def test_sqlite_error(self):
        dbms, evidence = _detect_db_error(
            'near "\'": syntax error'
        )
        assert dbms == "sqlite"

    def test_oracle_error(self):
        dbms, evidence = _detect_db_error("ORA-00907: missing right parenthesis")
        assert dbms == "oracle"
        assert evidence != ""

    def test_generic_error(self):
        dbms, evidence = _detect_db_error("SQL Error: syntax error in query")
        assert dbms in ("generic", "mysql", "mssql", "postgres", "sqlite", "oracle")

    def test_no_error(self):
        dbms, evidence = _detect_db_error("<html><body>Normal page</body></html>")
        assert dbms == ""
        assert evidence == ""


class TestDiffScore:
    def test_identical_strings_score_zero(self):
        assert _diff_score("hello", "hello") == pytest.approx(0.0)

    def test_completely_different_score_one(self):
        score = _diff_score("aaaa", "bbbb")
        assert score > 0.9

    def test_slightly_different(self):
        a = "<html>You are logged in as admin</html>"
        b = "<html>You are not logged in</html>"
        score = _diff_score(a, b)
        assert score > 0.0

    def test_single_line_change_detected(self):
        """Exclusive-line scoring should detect a single changed line in a large page."""
        common = "\n".join(f"<p>line {i}</p>" for i in range(100))
        a = common + "\n<p>User ID exists in the database.</p>"
        b = common + "\n<p>User ID is MISSING from the database.</p>"
        score = _diff_score(a, b)
        assert score > 0.0


class TestExtractMarker:
    def test_found(self):
        body = "<td>before BreachSQL_abc123 after</td>"
        result = _extract_marker(body, "BreachSQL_abc123")
        assert "BreachSQL_abc123" in result

    def test_not_found(self):
        result = _extract_marker("<html>nothing</html>", "BreachSQL_xyz")
        assert result == ""

    def test_extracts_wider_window(self):
        """Window should be large enough to capture SQL output like a version string."""
        long_suffix = "A" * 150
        body = f"prefix BreachSQL_abc123 {long_suffix}"
        result = _extract_marker(body, "BreachSQL_abc123")
        # At least 100 chars of the suffix should be captured
        assert len(result) > 100


class TestLenRatio:
    def test_identical_length(self):
        assert _len_ratio("abc", "abc") == pytest.approx(0.0)

    def test_both_empty(self):
        assert _len_ratio("", "") == pytest.approx(0.0)

    def test_one_empty(self):
        ratio = _len_ratio("hello", "")
        assert ratio == pytest.approx(1.0)

    def test_proportional(self):
        ratio = _len_ratio("abc", "abcde")
        assert 0.0 < ratio < 1.0


class TestHasStableBooleanSignal:
    def test_case_a_baseline_matches_true(self):
        """Case A: baseline resembles true response — signal is stable."""
        baseline  = "line1\nUser ID exists\nline3"
        true_resp = "line1\nUser ID exists\nline3"
        false_resp = "line1\nUser ID is MISSING\nline3"
        assert _has_stable_boolean_signal(baseline, true_resp, false_resp) is True

    def test_case_b_baseline_matches_false(self):
        """Case B: baseline resembles false response (empty param)."""
        baseline   = "line1\nUser ID is MISSING\nline3"
        true_resp  = "line1\nUser ID exists\nline3"
        false_resp = "line1\nUser ID is MISSING\nline3"
        assert _has_stable_boolean_signal(baseline, true_resp, false_resp) is True

    def test_no_signal_identical_responses(self):
        """When true == false, there is no boolean signal."""
        resp = "line1\nline2\nline3"
        assert _has_stable_boolean_signal(resp, resp, resp) is False

    def test_case_c_symmetric_small_diff(self):
        """Case C: symmetric exclusive lines, no CSRF tokens — should confirm."""
        common = "\n".join(f"<p>content {i}</p>" for i in range(50))
        true_resp  = common + "\n<p>Welcome admin</p>"
        false_resp = common + "\n<p>Access denied</p>"
        baseline   = common + "\n<p>Some other line</p>"
        assert _has_stable_boolean_signal(baseline, true_resp, false_resp) is True

    def test_case_c_rejects_csrf_tokens(self):
        """Case C must reject pages where exclusive lines look like CSRF tokens."""
        common = "\n".join(f"<p>line {i}</p>" for i in range(50))
        # Each side has a different 32-char hex token (typical CSRF token)
        true_resp  = common + "\n<input value='abcdef1234567890abcdef1234567890'>"
        false_resp = common + "\n<input value='0987654321fedcba0987654321fedcba'>"
        baseline   = common + "\n<input value='aabbccdd11223344aabbccdd11223344'>"
        assert _has_stable_boolean_signal(baseline, true_resp, false_resp) is False


class TestFetch:
    def test_baseline_uses_original_value(self):
        """Baseline (value=None) should send the original param value, not empty."""
        injector = MagicMock()
        r = MagicMock()
        r.text = "<html>baseline</html>"
        r.status_code = 200
        injector.inject_get.return_value = r

        surface = _surface(url="https://x.com/?q=42")
        _fetch(injector, surface["url"], surface["method"],
               surface["params"], "q", None)

        # The injector should have been called with value "42" (the original)
        call_args = injector.inject_get.call_args
        assert call_args[0][2] == "42"

    def test_payload_appended_to_original(self):
        """Payload should be appended to original value, not replace it."""
        injector = MagicMock()
        r = MagicMock()
        r.text = "<html>ok</html>"
        r.status_code = 200
        injector.inject_get.return_value = r

        surface = _surface(url="https://x.com/?q=1")
        _fetch(injector, surface["url"], surface["method"],
               surface["params"], "q", "' AND 1=1-- -")

        call_args = injector.inject_get.call_args
        injected_val = call_args[0][2]
        assert injected_val == "1' AND 1=1-- -"

    def test_http_429_returns_none(self):
        """HTTP 429 (rate limit) should return None to avoid false positives."""
        injector = MagicMock()
        r = MagicMock()
        r.text = "<html>Too Many Requests</html>"
        r.status_code = 429
        injector.inject_get.return_value = r

        surface = _surface()
        result = _fetch(injector, surface["url"], surface["method"],
                        surface["params"], "q", "' OR 1=1-- -")
        assert result is None

    def test_exception_returns_none(self):
        """Network error should return None, not raise."""
        injector = MagicMock()
        injector.inject_get.side_effect = ConnectionError("refused")

        surface = _surface()
        result = _fetch(injector, surface["url"], surface["method"],
                        surface["params"], "q", "'")
        assert result is None

    def test_post_method_uses_params_original(self):
        """POST baseline should use the original value from params dict."""
        injector = MagicMock()
        r = MagicMock()
        r.text = "<html>ok</html>"
        r.status_code = 200
        injector.post.return_value = r

        surface = _surface(url="https://x.com/", method="POST", param="id")
        surface["params"]["id"] = "99"
        _fetch(injector, surface["url"], "POST", surface["params"], "id", None)

        call_data = injector.post.call_args[1]["data"]
        assert call_data["id"] == "99"

    def test_second_url_two_step_pattern(self):
        """With second_url, injection goes to first URL, response read from second."""
        injector = MagicMock()
        r_inject = MagicMock()
        r_inject.text = "<html>injected</html>"
        r_inject.status_code = 200
        r_second = MagicMock()
        r_second.text = "<html>result from second url</html>"
        r_second.status_code = 200
        injector.post.return_value = r_inject
        injector.get.return_value = r_second

        result = _fetch(injector, "https://x.com/inject", "POST",
                        {"id": "1"}, "id", "' AND 1=1-- -",
                        second_url="https://x.com/result")

        injector.post.assert_called_once()
        injector.get.assert_called_once_with("https://x.com/result")
        assert strip_status_sentinel(result) == "<html>result from second url</html>"


class TestFindColumnCount:
    def _make_injector_for_order_by(self, break_at: int):
        """
        Returns an injector that gives a good response for ORDER BY 1..break_at-1
        and a 'bad' (content-changed) response for ORDER BY break_at and above.
        """
        injector = MagicMock()

        def _inject_get(url, param, value):
            r = MagicMock()
            r.status_code = 200
            import re
            m = re.search(r"ORDER BY (\d+)", value, re.IGNORECASE)
            if m and int(m.group(1)) >= break_at:
                r.text = "<html><p>Error</p></html>"
            else:
                r.text = "<html><p>normal content here</p><p>result row</p></html>"
            return r

        injector.inject_get.side_effect = _inject_get
        injector.post.side_effect = lambda url, data=None: _inject_get(url, "", "")
        return injector

    def test_detects_column_count(self):
        injector = self._make_injector_for_order_by(break_at=3)
        col_count = _find_column_count(
            url="https://x.com/?id=1", method="GET",
            params={"id": "1"}, param="id",
            evasion="none", injector=injector,
        )
        assert col_count == 2

    def test_returns_none_when_all_fail(self):
        """If all ORDER BY probes return None (network error), returns None."""
        injector = MagicMock()
        injector.inject_get.side_effect = Exception("network error")
        col_count = _find_column_count(
            url="https://x.com/?id=1", method="GET",
            params={"id": "1"}, param="id",
            evasion="none", injector=injector,
        )
        assert col_count is None

    def test_respects_max_cols_parameter(self):
        """max_cols parameter should cap the number of probes."""
        injector = MagicMock()
        r = MagicMock()
        r.text = "<html><p>normal content here</p></html>"
        r.status_code = 200
        injector.inject_get.return_value = r

        col_count = _find_column_count(
            url="https://x.com/?id=1", method="GET",
            params={"id": "1"}, param="id",
            evasion="none", injector=injector,
            max_cols=5,
        )
        # With all-good responses, last_ok should be 5 (max_cols)
        assert col_count == 5


class TestTestParam:
    def test_error_based_detection(self):
        """Should detect MySQL error in response and append an ErrorBasedFinding."""
        mysql_error = "You have an error in your SQL syntax near '1'"
        # The scanner appends payload to original value "1", so injected value is "1'"
        injector = _mock_injector({"1'": mysql_error, "'": mysql_error})
        opts = ScanOptions(technique="E", dbms="mysql", level=1)
        result = ScanResult(target="https://x.com/")

        scan_param(_surface(), ["none"], opts, injector, result)

        assert len(result.error_based) == 1
        assert result.error_based[0].dbms == "mysql"

    def test_boolean_detection(self):
        """Should detect boolean SQLi when true/false responses diverge."""
        injector = _mock_injector({
            # Full appended values (original "1" + payload)
            "1' AND '1'='1": "<html>Welcome admin</html>",
            "1' AND '1'='2": "<html>Error: invalid login</html>",
            # Also support raw payload keys (fallback)
            "' AND '1'='1": "<html>Welcome admin</html>",
            "' AND '1'='2": "<html>Error: invalid login</html>",
            "": "<html>Welcome admin</html>",
            "1":  "<html>Welcome admin</html>",
        })
        opts = ScanOptions(technique="B", level=1)
        result = ScanResult(target="https://x.com/")

        scan_param(_surface(), ["none"], opts, injector, result)

        assert len(result.boolean_based) == 1

    def test_baseline_failure_exits_early(self):
        """If the baseline fetch fails (returns None), scan_param should exit silently."""
        injector = MagicMock()
        injector.inject_get.side_effect = Exception("connection refused")
        injector.post.side_effect = Exception("connection refused")

        opts = ScanOptions(technique="EB", level=1)
        result = ScanResult(target="https://x.com/")
        scan_param(_surface(), ["none"], opts, injector, result)
        assert result.total_findings == 0

    def test_post_method_surface(self):
        """POST-method surface should use injector.post for payload delivery."""
        mysql_error = "You have an error in your SQL syntax"
        injector = MagicMock()

        def _post(url, data=None):
            r = MagicMock()
            val = str((data or {}).get("id", ""))
            r.text = mysql_error if "'" in val else "<html>OK</html>"
            r.status_code = 200
            return r

        injector.post.side_effect = _post
        injector.get_params.return_value = ["id"]

        opts = ScanOptions(technique="E", level=1)
        result = ScanResult(target="https://x.com/")
        surface = {"url": "https://x.com/", "method": "POST",
                   "params": {"id": "1"}, "single_param": "id"}
        scan_param(surface, ["none"], opts, injector, result)

        assert len(result.error_based) >= 1

    def test_no_finding_clean_response(self):
        """No findings if responses are all identical (no SQLi)."""
        injector = _mock_injector()
        opts = ScanOptions(technique="EB", level=1)
        result = ScanResult(target="https://x.com/")

        scan_param(_surface(), ["none"], opts, injector, result)

        assert result.total_findings == 0

    def test_technique_e_only_runs_error(self):
        """With technique='E', boolean tests should not run."""
        injector = _mock_injector()
        opts = ScanOptions(technique="E", level=1)
        result = ScanResult(target="https://x.com/")

        with patch("breachsql.engine._scanner.active._test_boolean") as mock_bool:
            scan_param(_surface(), ["none"], opts, injector, result)
            mock_bool.assert_not_called()

    def test_union_runs_at_level1(self):
        """Union detection should run at level=1 (no longer gated by level)."""
        injector = _mock_injector()
        opts = ScanOptions(technique="U", level=1)
        result = ScanResult(target="https://x.com/")

        with patch("breachsql.engine._scanner.active._test_union") as mock_union:
            scan_param(_surface(), ["none"], opts, injector, result)
            mock_union.assert_called_once()

    def test_union_runs_at_level2(self):
        """Union detection should run at level=2."""
        injector = _mock_injector()
        opts = ScanOptions(technique="U", level=2)
        result = ScanResult(target="https://x.com/")

        with patch("breachsql.engine._scanner.active._test_union") as mock_union:
            scan_param(_surface(), ["none"], opts, injector, result)
            mock_union.assert_called_once()

    def test_second_url_passed_through(self):
        """second_url in opts should be forwarded to _test_error_based."""
        injector = _mock_injector()
        opts = ScanOptions(technique="E", level=1, second_url="https://x.com/result")
        result = ScanResult(target="https://x.com/")

        with patch("breachsql.engine._scanner.active._test_error_based") as mock_err:
            scan_param(_surface(), ["none"], opts, injector, result)
            # second_url should be in the call arguments
            _, kwargs = mock_err.call_args if mock_err.call_args else ((), {})
            args = mock_err.call_args[0] if mock_err.call_args else ()
            assert "https://x.com/result" in args

    def test_union_not_detected_when_marker_only_in_error(self):
        """Union should NOT be reported when the marker only appears inside a
        DB error message (escaped payload reflected back in error text) rather
        than in actual extracted UNION data — regression test for the
        error-reflection false positive."""
        from breachsql.engine._scanner.active import _test_union
        from breachsql.engine.reporter import ScanResult
        from breachsql.engine._scanner.options import ScanOptions

        # Build a mock injector that for ORDER BY probes returns a 'good' baseline
        # response so that column count is determined as 1, then for the UNION
        # probe returns the marker *inside* an SQL error message.
        marker_holder: list[str] = []

        import breachsql.engine._scanner.active as _active
        original_make_marker = _active.make_marker

        def _capture_marker():
            m = original_make_marker()
            marker_holder.append(m)
            return m

        good_baseline = "<html><body><pre>ID: 1 First name: admin</pre></body></html>"

        def _inject_get(url, param, value):
            r = MagicMock()
            r.status_code = 200
            v = str(value)
            # ORDER BY 1 — looks OK (no error)
            if "ORDER BY 1" in v and "ORDER BY 10" not in v:
                r.text = good_baseline
            # ORDER BY 2 — triggers error (only 1 col)
            elif "ORDER BY" in v:
                r.text = "<html>You have an error in your SQL syntax</html>"
            elif marker_holder and marker_holder[0] in v:
                # Marker appears in error reflection — the evil case
                r.text = (
                    f"<html>You have an error in your SQL syntax near"
                    f" \\'{marker_holder[0]}\\' at line 1</html>"
                )
            else:
                r.text = good_baseline
            return r

        injector = MagicMock()
        injector.inject_get.side_effect = _inject_get

        opts = ScanOptions(technique="U", level=2, dbms="mysql")
        result = ScanResult(target="https://x.com/")
        surface = {
            "url": "https://x.com/?id=1",
            "method": "GET",
            "params": {"id": "1"},
            "single_param": "id",
        }

        with patch.object(_active, "make_marker", side_effect=_capture_marker):
            _test_union(
                surface["url"], surface["method"], surface["params"],
                surface["single_param"], "none", opts, injector, result,
            )

        # No union finding should be reported — the marker was only in an error
        assert len(result.union_based) == 0


# ---------------------------------------------------------------------------
# Paren-escape context detection tests
# ---------------------------------------------------------------------------

class TestParenEscapeContext:
    """Verify that the scanner detects SQLi in LIKE ('%value%') style queries."""

    def _make_paren_injector(self, marker: str):
        """
        Mock injector simulating: SELECT ... WHERE x LIKE ('%<value>%')
        Error-based: ')) triggers a syntax error.
        Union:       ')) UNION SELECT '<marker>',2,...-- returns the marker.
        Boolean:     ')) AND '1'='1'-- vs ')) AND '1'='2'-- differ.
        """
        good = "<html><body>Product: Foo</body></html>"
        error = "<html>SQLITE_ERROR: unrecognized token</html>"

        def _inject_get(url, param, value):
            r = MagicMock()
            r.status_code = 200
            v = str(value)
            if "'))" in v and marker in v:
                r.text = f"<html><body>{marker}</body></html>"
            elif "'))" in v and ("AND '1'='1" in v or "AND 1=1" in v):
                r.text = good  # true condition — same as baseline
            elif "'))" in v and ("AND '1'='2" in v or "AND 1=2" in v):
                r.text = "<html><body>No results</body></html>"
            elif "'))" in v:
                r.text = error
            else:
                r.text = good
            return r

        inj = MagicMock()
        inj.inject_get.side_effect = _inject_get
        inj.get_params.return_value = ["q"]
        inj.request_count = 0
        return inj

    def test_error_based_paren_context(self):
        from breachsql.engine._scanner.active import _test_error_based
        inj = self._make_paren_injector("MARKER")
        opts = ScanOptions(technique="E", dbms="sqlite")
        result = ScanResult(target="https://x.com/")
        _test_error_based(
            "https://x.com/?q=foo", "GET", {"q": "foo"}, "q",
            "none", opts, inj, result,
        )
        assert len(result.error_based) >= 1
        assert result.error_based[0].dbms in ("sqlite", "generic")

    def test_boolean_paren_context(self):
        from breachsql.engine._scanner.active import _test_boolean
        inj = self._make_paren_injector("MARKER")
        opts = ScanOptions(technique="B")
        result = ScanResult(target="https://x.com/")
        baseline = "<html><body>Product: Foo</body></html>"
        _test_boolean(
            "https://x.com/?q=foo", "GET", {"q": "foo"}, "q",
            baseline, "none", opts, inj, result,
        )
        assert len(result.boolean_based) >= 1

    def test_union_paren_context(self):
        from breachsql.engine._scanner.active import _test_union
        import breachsql.engine._scanner.active as _active

        marker_holder: list[str] = []
        orig = _active.make_marker

        def _cap():
            m = orig()
            marker_holder.append(m)
            return m

        good = "<html><body>Product: Foo</body></html>"
        error = "<html>SQLITE_ERROR: unrecognized token</html>"

        def _inject_get(url, param, value):
            r = MagicMock()
            r.status_code = 200
            v = str(value)
            if marker_holder and marker_holder[0] in v:
                # UNION probe — return marker in body only for paren-escape variants
                if "'))" in v:
                    r.text = f"<html><body>{marker_holder[0]}</body></html>"
                else:
                    r.text = error  # non-paren contexts fail
            elif "ORDER BY 1" in v and "ORDER BY 10" not in v and "ORDER BY 11" not in v:
                r.text = good  # col 1 is valid
            elif "ORDER BY" in v:
                r.text = error  # col > 1 triggers error → col_count = 1
            else:
                r.text = good
            return r

        inj = MagicMock()
        inj.inject_get.side_effect = _inject_get
        opts = ScanOptions(technique="U", level=2, dbms="sqlite")
        result = ScanResult(target="https://x.com/")

        with patch.object(_active, "make_marker", side_effect=_cap):
            _test_union(
                "https://x.com/?q=foo", "GET", {"q": "foo"}, "q",
                "none", opts, inj, result,
            )

        assert len(result.union_based) >= 1
        assert "'))" in result.union_based[0].payload


# ---------------------------------------------------------------------------
# JSON POST body injection tests
# ---------------------------------------------------------------------------

class TestJsonPostBody:
    """Verify that JSON POST surfaces use json_body=True and send correct Content-Type."""

    def test_fetch_uses_json_body_flag(self):
        """_fetch with json_body=True calls injector.post(url, json_body=...) not data=..."""
        inj = MagicMock()
        resp = MagicMock()
        resp.text = "<html>OK</html>"
        resp.status_code = 200
        inj.post.return_value = resp

        from breachsql.engine._scanner.active import _fetch
        result = _fetch(
            inj, "https://x.com/api/login", "POST",
            {"email": "admin@x.com", "password": "pass"}, "email",
            "' OR 1=1--", json_body=True,
        )
        # Should have been called with json_body kwarg, not data=
        call_kwargs = inj.post.call_args
        assert call_kwargs is not None
        # json_body should be set
        assert call_kwargs.kwargs.get("json_body") is not None or (
            len(call_kwargs.args) >= 2 and call_kwargs.args[1] is None
        ), "Expected json_body to be passed to injector.post"
        # data= should NOT be set (or be None)
        assert call_kwargs.kwargs.get("data") is None

    def test_scan_param_json_surface(self):
        """scan_param with json_body=True surface detects error-based SQLi via JSON POST."""
        error_html = "<html>SQLITE_ERROR: near \"'\" syntax error</html>"
        ok_html = "<html>OK logged in</html>"

        inj = MagicMock()
        def _post(url, data=None, json_body=None, **kw):
            r = MagicMock()
            r.status_code = 200
            body = json_body or data or {}
            val = str(body.get("email", ""))
            r.text = error_html if "'" in val else ok_html
            return r

        inj.post.side_effect = _post

        opts = ScanOptions(technique="E", dbms="sqlite")
        result = ScanResult(target="https://x.com/")
        surface = {
            "url": "https://x.com/api/login",
            "method": "POST",
            "params": {"email": "test@x.com", "password": "pass"},
            "single_param": "email",
            "json_body": True,
        }
        scan_param(surface, ["none"], opts, inj, result)
        assert len(result.error_based) >= 1


# ---------------------------------------------------------------------------
# PATH method injection tests
# ---------------------------------------------------------------------------

class TestPathInjection:
    def _make_path_injector(self, good_text="<html>OK</html>", error_text=None):
        """Build a mock injector that routes inject_path calls to canned responses."""
        inj = MagicMock()

        def _inject_path(url, index, value):
            r = MagicMock()
            r.status_code = 200
            if error_text and "'" in str(value):
                r.text = error_text
            else:
                r.text = good_text
            return r

        inj.inject_path.side_effect = _inject_path
        # Baseline inject_get shouldn't be called for PATH surfaces, but mock anyway
        r_ok = MagicMock()
        r_ok.text = good_text
        r_ok.status_code = 200
        inj.inject_get.return_value = r_ok
        return inj

    def test_fetch_path_calls_inject_path(self):
        """_fetch with method=PATH must call injector.inject_path, not inject_get."""
        inj = self._make_path_injector()
        resp = _fetch(inj, "https://x.com/order/123", "PATH",
                      {"id": "123"}, "id", "' OR 1=1--", path_index=2)
        assert resp is not None
        inj.inject_path.assert_called_once()
        inj.inject_get.assert_not_called()

    def test_fetch_path_index_passed_correctly(self):
        """The path_index argument must be forwarded to inject_path."""
        inj = self._make_path_injector()
        _fetch(inj, "https://x.com/a/b/c/123", "PATH",
               {"id": "123"}, "id", "'", path_index=3)
        call_args = inj.inject_path.call_args
        assert call_args[0][1] == 3  # second positional arg is the index

    def test_fetch_path_baseline_appends_nothing(self):
        """Baseline fetch (value=None) should pass original value unchanged."""
        inj = self._make_path_injector()
        _fetch(inj, "https://x.com/order/42", "PATH",
               {"id": "42"}, "id", None, path_index=2)
        inj.inject_path.assert_called_once()
        call_args = inj.inject_path.call_args
        # Third arg is the injected value — should equal original "42" unchanged
        assert call_args[0][2] == "42"

    def test_scan_param_path_surface_detects_error(self):
        """scan_param with method=PATH surface detects error-based SQLi."""
        import json as _json

        error_html = "<html>You have an error in your SQL syntax</html>"
        ok_html    = "<html>Order found</html>"

        inj = MagicMock()
        def _inject_path(url, index, value):
            r = MagicMock()
            r.status_code = 200
            r.text = error_html if "'" in str(value) else ok_html
            return r
        inj.inject_path.side_effect = _inject_path

        opts    = ScanOptions(technique="E", dbms="mysql")
        result  = ScanResult(target="https://x.com/")
        surface = {
            "url":          "https://x.com/rest/track-order/:id",
            "method":       "PATH",
            "params":       {"id": "1"},
            "single_param": "id",
            "path_index":   3,
        }
        scan_param(surface, ["none"], opts, inj, result)
        assert len(result.error_based) >= 1
        assert result.error_based[0].method == "PATH"
