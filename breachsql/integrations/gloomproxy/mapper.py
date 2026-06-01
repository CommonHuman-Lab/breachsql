# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""Map native BreachSQL findings → GloomProxy SDK Finding objects."""
from __future__ import annotations

import dataclasses

from gloomproxy_sdk import Finding

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

_SCANNER = "breachsql"

# ── per-type mappers ──────────────────────────────────────────────────────────

def _map_error(f: ErrorBasedFinding) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="error_based_sqli",
        severity="high",
        target=f.url,
        evidence=f.evidence or f"DBMS error pattern detected ({f.dbms}) via parameter '{f.parameter}'",
        title=f"Error-Based SQLi — {f.parameter}",
        description=f"SQL error returned by {f.dbms} when injecting parameter '{f.parameter}'.",
        confidence=0.97,
        request=f"Parameter: {f.parameter}\nMethod: {f.method}\nPayload: {f.payload}",
        extra={"parameter": f.parameter, "method": f.method, "payload": f.payload, "dbms": f.dbms},
        tags=["sqli", "error-based", f"dbms:{f.dbms}"],
    )


def _map_boolean(f: BooleanFinding) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="boolean_based_sqli",
        severity="high",
        target=f.url,
        evidence=f.evidence or f"Boolean divergence (score {f.diff_score:.2f}) in parameter '{f.parameter}'",
        title=f"Boolean-Based SQLi — {f.parameter}",
        description="Distinct true/false responses indicate boolean-based blind SQL injection.",
        confidence=0.85 if not f.confirmed else 0.95,
        request=f"Parameter: {f.parameter}\nMethod: {f.method}\nTrue: {f.payload_true}\nFalse: {f.payload_false}",
        extra={"parameter": f.parameter, "method": f.method, "diff_score": f.diff_score, "confirmed": f.confirmed},
        tags=["sqli", "boolean-based", "blind"],
    )


def _map_time(f: TimeFinding) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="time_based_sqli",
        severity="high",
        target=f.url,
        evidence=f"Response delayed {f.observed_delay:.1f}s (threshold {f.threshold}s) for parameter '{f.parameter}'",
        title=f"Time-Based Blind SQLi — {f.parameter}",
        description=f"Time-based blind SQL injection in parameter '{f.parameter}' ({f.dbms}).",
        confidence=0.80,
        request=f"Parameter: {f.parameter}\nMethod: {f.method}\nPayload: {f.payload}",
        extra={"parameter": f.parameter, "method": f.method, "payload": f.payload, "dbms": f.dbms, "observed_delay": f.observed_delay},
        tags=["sqli", "time-based", "blind", f"dbms:{f.dbms}"],
    )


def _map_union(f: UnionFinding) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="union_based_sqli",
        severity="high",
        target=f.url,
        evidence=f"UNION SELECT with {f.column_count} columns reflected in response for parameter '{f.parameter}'",
        title=f"Union-Based SQLi — {f.parameter}",
        description="UNION-based SQL injection allows direct data extraction from the database.",
        confidence=0.97,
        request=f"Parameter: {f.parameter}\nMethod: {f.method}\nPayload: {f.payload}",
        extra={"parameter": f.parameter, "method": f.method, "payload": f.payload, "column_count": f.column_count, "extracted": f.extracted},
        tags=["sqli", "union-based", "data-extraction"],
    )


def _map_oob(f: OOBFinding) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="oob_sqli",
        severity="high",
        target=f.url,
        evidence=f"OOB payload injected in parameter '{f.parameter}' — callback: {f.callback_url}",
        title=f"Out-of-Band SQLi — {f.parameter}",
        description="Out-of-band SQL injection payload injected. Confirm via callback DNS/HTTP listener.",
        confidence=0.70 if not f.confirmed else 0.95,
        request=f"Parameter: {f.parameter}\nMethod: {f.method}\nPayload: {f.payload}",
        extra={"parameter": f.parameter, "method": f.method, "payload": f.payload, "callback_url": f.callback_url, "confirmed": f.confirmed},
        tags=["sqli", "oob", "blind"],
    )


def _map_stacked(f: StackedFinding) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="stacked_sqli",
        severity="critical",
        target=f.url,
        evidence=f.evidence or f"Stacked query executed ({f.dbms}) via parameter '{f.parameter}'",
        title=f"Stacked Query SQLi — {f.parameter}",
        description=f"Stacked queries confirmed in parameter '{f.parameter}'. Arbitrary SQL statements can be executed.",
        confidence=0.95,
        request=f"Parameter: {f.parameter}\nMethod: {f.method}\nPayload: {f.payload}",
        extra={"parameter": f.parameter, "method": f.method, "payload": f.payload, "dbms": f.dbms},
        tags=["sqli", "stacked", "rce-adjacent", f"dbms:{f.dbms}"],
    )


def _map_extraction(f: ExtractionFinding) -> Finding:
    return Finding(
        scanner=_SCANNER,
        type="sqli_extraction",
        severity="critical",
        target=f.url,
        evidence=f"Extracted via {f.mode}: {f.expr} = {f.value[:100]}",
        title=f"SQLi Data Extraction — {f.parameter}",
        description=f"Blind extraction via {f.mode} confirmed. Expression '{f.expr}' returned live data.",
        confidence=1.0,
        request=f"Parameter: {f.parameter}\nMethod: {f.method}\nExpression: {f.expr}",
        extra={"parameter": f.parameter, "method": f.method, "expr": f.expr, "value": f.value, "mode": f.mode},
        tags=["sqli", "extraction", f"mode:{f.mode}"],
    )


# ── main entry point ──────────────────────────────────────────────────────────

_MAPPERS = [
    ("error_based",   _map_error),
    ("boolean_based", _map_boolean),
    ("time_based",    _map_time),
    ("union_based",   _map_union),
    ("oob",           _map_oob),
    ("stacked",       _map_stacked),
    ("extracted",     _map_extraction),
]


def map_results(result: ScanResult) -> list[Finding]:
    """Convert a BreachSQL ScanResult into a list of SDK Finding objects."""
    findings: list[Finding] = []
    for attr, mapper in _MAPPERS:
        for native in getattr(result, attr, []):
            try:
                findings.append(mapper(native).validate())
            except Exception:
                pass
    return findings
