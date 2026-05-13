# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""BreachSQL — engine/reporter.py — scan result dataclasses and serialisation."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from commonhuman_cli.reporter import ScanResultBase


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FindingType(str, Enum):
    ERROR_BASED  = "error_based_sqli"
    BOOLEAN      = "boolean_based_sqli"
    TIME_BASED   = "time_based_sqli"
    UNION_BASED  = "union_based_sqli"
    OOB          = "oob_sqli"
    STACKED      = "stacked_sqli"
    EXTRACTION   = "extraction"


# ---------------------------------------------------------------------------
# Finding dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ErrorBasedFinding:
    """DB error pattern visible in response — confirmed SQLi."""
    url:       str
    parameter: str
    method:    str
    payload:   str
    dbms:      str
    evidence:  str = ""


@dataclass
class BooleanFinding:
    """True/false response divergence — likely SQLi."""
    url:           str
    parameter:     str
    method:        str
    payload_true:  str
    payload_false: str
    diff_score:    float
    confirmed:     bool
    evidence:      str = ""


@dataclass
class TimeFinding:
    """Response time delta exceeds threshold — time-based blind SQLi."""
    url:            str
    parameter:      str
    method:         str
    payload:        str
    dbms:           str
    observed_delay: float
    threshold:      int


@dataclass
class UnionFinding:
    """UNION SELECT reflection confirmed — union-based SQLi."""
    url:          str
    parameter:    str
    method:       str
    payload:      str
    column_count: int
    extracted:    str = ""


@dataclass
class OOBFinding:
    """Out-of-band payload injected — callback confirmation required externally."""
    url:          str
    parameter:    str
    method:       str
    payload:      str
    callback_url: str
    confirmed:    bool = False


@dataclass
class StackedFinding:
    """Stacked (batched) query injection confirmed — second statement was executed."""
    url:       str
    parameter: str
    method:    str
    payload:   str
    dbms:      str
    evidence:  str = ""


@dataclass
class ExtractionFinding:
    """Data extracted via blind char-by-char extraction (boolean or time mode)."""
    url:       str
    parameter: str
    method:    str
    expr:      str
    value:     str
    mode:      str


# ---------------------------------------------------------------------------
# Finding type → list attribute mapping
# ---------------------------------------------------------------------------

_FINDING_LISTS: List[tuple[str, FindingType]] = [
    ("error_based",   FindingType.ERROR_BASED),
    ("boolean_based", FindingType.BOOLEAN),
    ("time_based",    FindingType.TIME_BASED),
    ("union_based",   FindingType.UNION_BASED),
    ("oob",           FindingType.OOB),
    ("stacked",       FindingType.STACKED),
    ("extracted",     FindingType.EXTRACTION),
]


# ---------------------------------------------------------------------------
# Top-level ScanResult
# ---------------------------------------------------------------------------

@dataclass
class ScanResult(ScanResultBase):
    # DBMS (auto-detected during scan) — BreachSQL-specific
    dbms_detected: Optional[str] = None

    # Findings
    error_based:   List[ErrorBasedFinding] = field(default_factory=list)
    boolean_based: List[BooleanFinding]    = field(default_factory=list)
    time_based:    List[TimeFinding]       = field(default_factory=list)
    union_based:   List[UnionFinding]      = field(default_factory=list)
    oob:           List[OOBFinding]        = field(default_factory=list)
    stacked:       List[StackedFinding]    = field(default_factory=list)
    extracted:     List[ExtractionFinding] = field(default_factory=list)

    # --- Append helpers -------------------------------------------------------

    def append_error_based(self, f)   -> None: self._append("error_based", f)
    def append_boolean(self, f)       -> None: self._append("boolean_based", f)
    def append_time(self, f)          -> None: self._append("time_based", f)
    def append_union(self, f)         -> None: self._append("union_based", f)
    def append_oob(self, f)           -> None: self._append("oob", f)
    def append_stacked(self, f)       -> None: self._append("stacked", f)

    def append_extraction(self, f) -> None:
        with self._lock:
            for existing in self.extracted:
                if existing.parameter == f.parameter and existing.expr == f.expr:
                    return
            self.extracted.append(f)

    # --- Computed properties --------------------------------------------------

    @property
    def total_findings(self) -> int:
        return sum(len(getattr(self, attr)) for attr, _ in _FINDING_LISTS)

    def to_dict(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        for attr, ftype in _FINDING_LISTS:
            for item in getattr(self, attr):
                d = dataclasses.asdict(item)
                d["type"] = ftype.value
                findings.append(d)

        result = self._base_dict()
        result["dbms_detected"] = self.dbms_detected
        result["total_findings"] = self.total_findings
        result["findings"] = findings
        return result
