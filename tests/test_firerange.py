# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
tests/test_firerange.py — end-to-end BreachSQL scanner tests against the
BreachSQL Fire Range (deliberately vulnerable Flask + MySQL + PostgreSQL
+ SQLite stack).

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
    """Resolve the Fire Range base URL and skip if unreachable."""
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


def _msg(result) -> str:
    d = result.to_dict()
    return (
        f"No findings detected.\n"
        f"Findings: {d['findings']}\n"
        f"Errors:   {d['errors']}\n"
        f"Log:      {d['log']}"
    )


# ===========================================================================
# T I E R  0 — Sanity
# ===========================================================================

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
    """/api/challenges returns all 33 challenges (no flags exposed)."""
    r = requests.get(f"{firerange}/api/challenges", timeout=5)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list) and len(data) >= 33
    first = data[0]
    assert "flag" not in first
    assert {"challenge_id", "tier", "title", "points"} <= first.keys()


# ===========================================================================
# M Y S Q L — Tier 1  (Beginner)
# ===========================================================================

@pytest.mark.firerange
def test_t1a_error_get_numeric(firerange):
    """T1-A: Integer param, raw concat, error leaks SQL syntax."""
    result = _scan(
        f"{firerange}/challenges/t1/users?id=1",
        dbms="mysql", technique="E", risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t1a_clean_baseline(firerange):
    """T1-A: Clean request returns expected row (id=1 → admin)."""
    r = requests.get(f"{firerange}/challenges/t1/users?id=1", timeout=5)
    assert r.status_code == 200
    assert r.json()[0]["username"] == "admin"


@pytest.mark.firerange
def test_t1b_union_secrets(firerange):
    """T1-B: UNION extraction from t1_secrets (2-column)."""
    result = _scan(
        f"{firerange}/challenges/t1/secrets?id=1",
        dbms="mysql", technique="U", level=2, risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t1c_double_quote_error(firerange):
    """T1-C: Double-quote context error injection."""
    result = _scan(
        f"{firerange}/challenges/t1/notes?author=admin",
        dbms="mysql", technique="E", risk=1,
    )
    assert result.total_findings > 0, _msg(result)


# ===========================================================================
# M Y S Q L — Tier 2  (Intermediate)
# ===========================================================================

@pytest.mark.firerange
def test_t2a_boolean_blind(firerange):
    """T2-A: String param boolean-blind (200 vs 404)."""
    result = _scan(
        f"{firerange}/challenges/t2/lookup?name=admin",
        dbms="mysql", technique="B", risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t2b_post_login_error(firerange):
    """T2-B: POST login form, error-based (username field)."""
    result = _scan(
        f"{firerange}/challenges/t2/login",
        dbms="mysql", technique="E",
        data="username=admin&password=secret",
        risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t2b_post_login_boolean(firerange):
    """T2-B: POST login form, boolean-blind (password field)."""
    result = _scan(
        f"{firerange}/challenges/t2/login",
        dbms="mysql", technique="B",
        data="username=admin&password=secret",
        risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t2c_or_based_boolean(firerange):
    """T2-C: OR-based boolean-blind (risk 2 required)."""
    result = _scan(
        f"{firerange}/challenges/t2/lookup?name=nobody",
        dbms="mysql", technique="B", risk=2,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t2d_second_step(firerange):
    """T2-D: Two-step injection — inject in /search, read result at /inbox."""
    result = _scan(
        f"{firerange}/challenges/t2/search?user=admin",
        dbms="mysql", technique="B",
        second_url=f"{firerange}/challenges/t2/inbox",
        risk=1,
    )
    assert result.total_findings > 0, _msg(result)


# ===========================================================================
# M Y S Q L — Tier 3  (Advanced)
# ===========================================================================

@pytest.mark.firerange
def test_t3a_time_blind(firerange):
    """T3-A: String param, MySQL SLEEP() time-blind."""
    result = _scan(
        f"{firerange}/challenges/t3/search?name=admin",
        dbms="mysql", technique="T",
        time_threshold=3, risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t3b_path_param(firerange):
    """T3-B: Path-parameter injection (/challenges/t3/item/1)."""
    result = _scan(
        f"{firerange}/challenges/t3/item/1",
        dbms="mysql", technique="E",
        path_params=["id"], risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t3c_union_3col(firerange):
    """T3-C: 3-column UNION extraction."""
    result = _scan(
        f"{firerange}/challenges/t3/products?id=1",
        dbms="mysql", technique="U", level=2, risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t3d_union_5col(firerange):
    """T3-D: 5-column UNION extraction."""
    result = _scan(
        f"{firerange}/challenges/t3/catalog?id=1",
        dbms="mysql", technique="U", level=2, risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t3e_paren_context(firerange):
    """T3-E: Boolean-blind inside parenthesised WHERE clause."""
    result = _scan(
        f"{firerange}/challenges/t3/account?username=jsmith",
        dbms="mysql", technique="B", risk=1,
    )
    assert result.total_findings > 0, _msg(result)


# ===========================================================================
# M Y S Q L — Tier 4  (Expert)
# ===========================================================================

@pytest.mark.firerange
def test_t4a_comment_filter_bypass(firerange):
    """T4-A: Inline comment WAF bypass (-- and # stripped, need /**/)."""
    result = _scan(
        f"{firerange}/challenges/t4/filtered?id=1",
        dbms="mysql", technique="E", risk=2,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t4b_json_body(firerange):
    """T4-B: JSON-body POST injection."""
    result = _scan(
        f"{firerange}/challenges/t4/api/user",
        dbms="mysql", technique="E",
        data='{"user_id": 1}',
        risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t4c_stacked(firerange):
    """T4-C: Stacked-injectable endpoint confirmed via error-based."""
    result = _scan(
        f"{firerange}/challenges/t4/stacked?id=1",
        dbms="mysql", technique="E", risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t4d_numeric_time_blind(firerange):
    """T4-D: Time-blind in a string context (val= param, no quote needed for sleep)."""
    result = _scan(
        f"{firerange}/challenges/t4/timer?val=x",
        dbms="mysql", technique="T",
        time_threshold=3, risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t4e_cookie_injection(firerange):
    """T4-E: Cookie-based injection (session_id header)."""
    result = _scan(
        f"{firerange}/challenges/t4/profile",
        dbms="mysql", technique="E",
        cookies="session_id=sess_abc123",
        cookie_params=["session_id"],
        risk=1,
    )
    assert result.total_findings > 0, _msg(result)


# ===========================================================================
# M Y S Q L — Tier 5  (Legend)
# ===========================================================================

@pytest.mark.firerange
def test_t5a_full_chain(firerange):
    """T5-A: Full multi-technique scan; must find ≥1 finding."""
    result = _scan(
        f"{firerange}/challenges/t5/report?id=1",
        dbms="mysql", technique="EBTUS", level=2, risk=2,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_t5b_crawl_and_conquer(firerange):
    """T5-B: Dashboard endpoint — injectable key= param, error-based extraction."""
    result = _scan(
        f"{firerange}/challenges/t5/dashboard?key=secret",
        dbms="mysql", technique="E", level=2, risk=1,
    )
    assert result.total_findings > 0, _msg(result)


# ===========================================================================
# P O S T G R E S Q L   challenges
# ===========================================================================

@pytest.mark.firerange
def test_pg1a_error_based(firerange):
    """PG1-A: PostgreSQL error-based (CAST type mismatch)."""
    result = _scan(
        f"{firerange}/challenges/pg/users?id=1",
        dbms="postgres", technique="E", risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_pg1b_boolean_blind(firerange):
    """PG1-B: PostgreSQL boolean-blind (200 vs 404)."""
    result = _scan(
        f"{firerange}/challenges/pg/secrets?name=flag",
        dbms="postgres", technique="B", risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_pg2a_time_blind(firerange):
    """PG2-A: PostgreSQL time-blind via pg_sleep()."""
    result = _scan(
        f"{firerange}/challenges/pg/employees?name=Jane+Doe",
        dbms="postgres", technique="T",
        time_threshold=3, risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_pg2b_union(firerange):
    """PG2-B: PostgreSQL UNION-based extraction."""
    result = _scan(
        f"{firerange}/challenges/pg/orders?id=1",
        dbms="postgres", technique="U", level=2, risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_pg2c_stacked(firerange):
    """PG2-C: PostgreSQL stacked query injection."""
    result = _scan(
        f"{firerange}/challenges/pg/logs?ip=10.0.0.1",
        dbms="postgres", technique="S", risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_pg3a_path_param(firerange):
    """PG3-A: PostgreSQL path-parameter injection."""
    result = _scan(
        f"{firerange}/challenges/pg/order/1",
        dbms="postgres", technique="E",
        path_params=["id"], risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_pg3b_post_login(firerange):
    """PG3-B: PostgreSQL POST login form injection."""
    result = _scan(
        f"{firerange}/challenges/pg/login",
        dbms="postgres", technique="E",
        data="username=admin&password=x",
        risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_pg4a_legend(firerange):
    """PG4-A: PostgreSQL full-chain legend challenge."""
    result = _scan(
        f"{firerange}/challenges/pg/report?id=1",
        dbms="postgres", technique="EBTUS", level=2, risk=2,
    )
    assert result.total_findings > 0, _msg(result)


# ===========================================================================
# S Q L I T E   challenges
# ===========================================================================

@pytest.mark.firerange
def test_sq1a_error_based(firerange):
    """SQ1-A: SQLite error-based (CAST type mismatch)."""
    result = _scan(
        f"{firerange}/challenges/sq/users?id=1",
        dbms="sqlite", technique="E", risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_sq1b_boolean_blind(firerange):
    """SQ1-B: SQLite boolean-blind (200 vs 404)."""
    result = _scan(
        f"{firerange}/challenges/sq/secrets?name=flag",
        dbms="sqlite", technique="B", risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_sq2a_time_blind(firerange):
    """SQ2-A: SQLite time-blind via randomblob()."""
    result = _scan(
        f"{firerange}/challenges/sq/files?owner=admin",
        dbms="sqlite", technique="T",
        time_threshold=3, risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_sq2b_union(firerange):
    """SQ2-B: SQLite UNION-based extraction."""
    result = _scan(
        f"{firerange}/challenges/sq/users?id=1",
        dbms="sqlite", technique="U", level=2, risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_sq2c_stacked(firerange):
    """SQ2-C: SQLite stacked query injection."""
    result = _scan(
        f"{firerange}/challenges/sq/files?owner=admin",
        dbms="sqlite", technique="S", risk=1,
    )
    assert result.total_findings > 0, _msg(result)


@pytest.mark.firerange
def test_sq3a_legend(firerange):
    """SQ3-A: SQLite full-chain legend challenge."""
    result = _scan(
        f"{firerange}/challenges/sq/report?id=1",
        dbms="sqlite", technique="EBTUS", level=2, risk=2,
    )
    assert result.total_findings > 0, _msg(result)


# ===========================================================================
# Flag submission  (manual player workflow)
# ===========================================================================

@pytest.mark.firerange
def test_flag_submission_rejects_wrong(firerange):
    """POST /api/submit-flag with a bogus flag returns incorrect."""
    r = requests.post(
        f"{firerange}/api/submit-flag",
        json={"player": "CommonHuman", "challenge_id": "t1a", "flag": "WRONG_FLAG"},
        timeout=5,
    )
    assert r.status_code in (400, 200)
    assert r.json().get("correct") is False or r.status_code == 400


@pytest.mark.firerange
def test_flag_submission_accepts_correct(firerange):
    """POST /api/submit-flag with the real t1a flag returns correct=True."""
    r = requests.post(
        f"{firerange}/api/submit-flag",
        json={"player": "pytest", "challenge_id": "t1a", "flag": "FIRE{t1a_integer_error_based}"},
        timeout=5,
    )
    assert r.status_code == 200
    assert r.json().get("correct") is True
