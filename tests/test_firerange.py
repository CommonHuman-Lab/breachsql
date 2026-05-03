# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
tests/test_firerange.py — end-to-end BreachSQL scanner tests against the
BreachSQL Fire Range (deliberately vulnerable Flask + MySQL stack).

The Fire Range is part of OctoRig (https://github.com/CommonHuman-Lab/OctoRig)
and must be started manually before running these tests:

    cd /path/to/OctoRig && ./octorig.sh start 7

If the Fire Range is unreachable, ALL tests in this file are skipped
automatically — the regular CI/unit suite is never affected.

Running
───────
    # firerange tests only
    pytest -m firerange -v

    # everything except firerange (CI-safe)
    pytest -m "not firerange"
"""

from __future__ import annotations

import time

import pytest
import requests

# ---------------------------------------------------------------------------
# Fire Range URL — change this if you run it on a different host/port
# ---------------------------------------------------------------------------

FIRERANGE_URL = "http://localhost:17476"

_HEALTH_TIMEOUT = 10  # seconds to wait for a health probe


def _is_reachable(url: str, timeout: int = _HEALTH_TIMEOUT) -> bool:
    """Return True if the fire range health endpoint responds within *timeout* s."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = requests.get(f"{url}/health", timeout=3)
            if r.status_code == 200 and r.json().get("status") == "ok":
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


# ---------------------------------------------------------------------------
# Session-scoped fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def firerange():
    """
    Resolve the Fire Range base URL and skip if unreachable.
    """
    base_url = FIRERANGE_URL.rstrip("/")
    if not _is_reachable(base_url):
        pytest.skip(
            f"Fire Range at {base_url} is not reachable — start it with: "
            f"./octorig.sh start 7"
        )

    yield base_url


# ---------------------------------------------------------------------------
# Scanner helper
# ---------------------------------------------------------------------------

def _scan(url: str, **kwargs):
    """Lazily import and run a BreachSQL scan so imports only happen at runtime."""
    from breachsql.engine import scan, ScanOptions
    opts = ScanOptions(timeout=10, **kwargs)
    return scan(url, opts)


# ---------------------------------------------------------------------------
# T I E R  0 — Sanity
# ---------------------------------------------------------------------------

@pytest.mark.firerange
def test_health(firerange):
    """Fire Range responds with status=ok."""
    r = requests.get(f"{firerange}/health", timeout=5)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


@pytest.mark.firerange
def test_challenge_index(firerange):
    """/ returns the HTML challenge index page."""
    r = requests.get(f"{firerange}/", timeout=5)
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")


@pytest.mark.firerange
def test_scoreboard_json(firerange):
    """/api/scoreboard returns a JSON list."""
    r = requests.get(f"{firerange}/api/scoreboard", timeout=5)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


@pytest.mark.firerange
def test_challenge_list_json(firerange):
    """/api/challenges returns a non-empty list of challenges."""
    r = requests.get(f"{firerange}/api/challenges", timeout=5)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list) and len(data) > 0
    first = data[0]
    assert {"id", "tier", "title", "points"} <= first.keys()


# ---------------------------------------------------------------------------
# T I E R  1 — Beginner (numeric GET param, error-based)
# ---------------------------------------------------------------------------

@pytest.mark.firerange
def test_t1_error_get_numeric(firerange):
    """T1-A: Integer param, raw concat, error leaks SQL syntax."""
    result = _scan(
        f"{firerange}/challenges/t1/users?id=1",
        dbms="mysql", technique="E", risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t1_clean_baseline(firerange):
    """T1-A: Clean request returns expected data (id=1 → admin)."""
    r = requests.get(f"{firerange}/challenges/t1/users?id=1", timeout=5)
    assert r.status_code == 200
    rows = r.json()
    assert rows[0]["username"] == "admin"


@pytest.mark.firerange
def test_t1_flag_in_secrets(firerange):
    """T1-B: UNION extract secret flag from secrets table."""
    result = _scan(
        f"{firerange}/challenges/t1/secrets?id=1",
        dbms="mysql", technique="U", level=2, risk=1,
    )
    assert result.total_findings > 0, _msg(result)


# ---------------------------------------------------------------------------
# T I E R  2 — Intermediate (string GET param, boolean-blind, POST form)
# ---------------------------------------------------------------------------

@pytest.mark.firerange
def test_t2_boolean_blind(firerange):
    """T2-A: String param, boolean-blind (200 vs 404)."""
    result = _scan(
        f"{firerange}/challenges/t2/lookup?name=admin",
        dbms="mysql", technique="B", risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t2_post_login_error(firerange):
    """T2-B: POST login form, error-based (username field)."""
    result = _scan(
        f"{firerange}/challenges/t2/login",
        dbms="mysql", technique="E",
        data="username=admin&password=secret",
        risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t2_post_login_boolean(firerange):
    """T2-B: POST login form, boolean-blind (password field)."""
    result = _scan(
        f"{firerange}/challenges/t2/login",
        dbms="mysql", technique="B",
        data="username=admin&password=secret",
        risk=1,
    )
    assert result.total_findings > 0, _msg(result)


# ---------------------------------------------------------------------------
# T I E R  3 — Advanced (time-blind, path param, second-order)
# ---------------------------------------------------------------------------

@pytest.mark.firerange
def test_t3_time_blind(firerange):
    """T3-A: String param, time-blind SLEEP injection."""
    result = _scan(
        f"{firerange}/challenges/t3/search?name=admin",
        dbms="mysql", technique="T",
        time_threshold=3, risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t3_path_param(firerange):
    """T3-B: Path-parameter injection (/challenges/t3/item/1)."""
    result = _scan(
        f"{firerange}/challenges/t3/item/1",
        dbms="mysql", technique="E",
        path_params=["id"], risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t3_union_multicolumn(firerange):
    """T3-C: 3-column UNION extraction."""
    result = _scan(
        f"{firerange}/challenges/t3/products?id=1",
        dbms="mysql", technique="U", level=2, risk=1,
    )
    assert result.total_findings > 0, _msg(result)


# ---------------------------------------------------------------------------
# T I E R  4 — Expert (WAF-like filter, JSON body, stacked)
# ---------------------------------------------------------------------------

@pytest.mark.firerange
def test_t4_comment_filter_bypass(firerange):
    """T4-A: Inline comment WAF bypass (-- and # stripped, need /**/)."""
    result = _scan(
        f"{firerange}/challenges/t4/filtered?id=1",
        dbms="mysql", technique="E", risk=2,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t4_json_body(firerange):
    """T4-B: JSON-body POST injection."""
    result = _scan(
        f"{firerange}/challenges/t4/api/user",
        dbms="mysql", technique="E",
        data='{"user_id": 1}',
        risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t4_stacked_injection_point(firerange):
    """T4-C: Stacked-injectable endpoint confirmed via error-based."""
    result = _scan(
        f"{firerange}/challenges/t4/stacked?id=1",
        dbms="mysql", technique="E", risk=1,
    )
    assert result.total_findings > 0, _msg(result)


# ---------------------------------------------------------------------------
# T I E R  5 — Legend (second-order, out-of-path, full chain)
# ---------------------------------------------------------------------------

@pytest.mark.firerange
def test_t5_full_scan_all_techniques(firerange):
    """T5: Full multi-technique scan on a rich endpoint; must find ≥1 vuln."""
    result = _scan(
        f"{firerange}/challenges/t5/report?id=1",
        dbms="mysql", technique="EBTUS", level=2, risk=2,
    )
    assert result.total_findings > 0, _msg(result)


# ---------------------------------------------------------------------------
# Flag submission (manual player workflow)
# ---------------------------------------------------------------------------

@pytest.mark.firerange
def test_flag_submission_rejects_wrong(firerange):
    """POST /api/submit-flag with a bogus flag returns 400/incorrect."""
    r = requests.post(
        f"{firerange}/api/submit-flag",
        json={"player": "pytest", "challenge_id": "t1a", "flag": "WRONG_FLAG"},
        timeout=5,
    )
    assert r.status_code in (400, 200)
    body = r.json()
    assert body.get("correct") is False or r.status_code == 400


@pytest.mark.firerange
def test_flag_submission_accepts_correct(firerange):
    """POST /api/submit-flag with the real flag for t1a returns correct=True."""
    # The flag for t1a is FIRE{t1a_integer_error_based}
    r = requests.post(
        f"{firerange}/api/submit-flag",
        json={"player": "pytest", "challenge_id": "t1a", "flag": "FIRE{t1a_integer_error_based}"},
        timeout=5,
    )
    assert r.status_code == 200
    assert r.json().get("correct") is True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _msg(result) -> str:
    d = result.to_dict()
    return (
        f"No findings detected.\n"
        f"Findings: {d['findings']}\n"
        f"Errors:   {d['errors']}\n"
        f"Log:      {d['log']}"
    )
