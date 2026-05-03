# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""BreachSQL — engine/reporter.py — scan result dataclasses and serialisation."""

from __future__ import annotations

import dataclasses
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


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
    dbms:      str          # detected DBMS name or "unknown"
    evidence:  str = ""     # snippet of the error message from the response


@dataclass
class BooleanFinding:
    """True/false response divergence — likely SQLi."""
    url:           str
    parameter:     str
    method:        str
    payload_true:  str
    payload_false: str
    diff_score:    float    # 0.0–1.0 similarity distance; higher = more different
    confirmed:     bool     # True if diff_score exceeds high-confidence threshold
    evidence:      str = ""


@dataclass
class TimeFinding:
    """Response time delta exceeds threshold — time-based blind SQLi."""
    url:            str
    parameter:      str
    method:         str
    payload:        str
    dbms:           str
    observed_delay: float   # seconds the response actually took
    threshold:      int     # configured threshold in seconds


@dataclass
class UnionFinding:
    """UNION SELECT reflection confirmed — union-based SQLi."""
    url:          str
    parameter:    str
    method:       str
    payload:      str
    column_count: int
    extracted:    str = ""  # data extracted via the UNION column


@dataclass
class OOBFinding:
    """Out-of-band payload injected — requires callback confirmation."""
    url:          str
    parameter:    str
    method:       str
    payload:      str
    callback_url: str


@dataclass
class StackedFinding:
    """Stacked (batched) query injection confirmed — second statement was executed."""
    url:       str
    parameter: str
    method:    str
    payload:   str
    dbms:      str
    evidence:  str = ""  # first 200 chars of the diverged response


@dataclass
class ExtractionFinding:
    """Data extracted via blind char-by-char extraction (boolean or time mode)."""
    url:       str
    parameter: str
    method:    str
    expr:      str    # SQL expression that was extracted
    value:     str    # extracted string value
    mode:      str    # "boolean" or "time"


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
class ScanResult:
    # Meta
    target:      str
    started_at:  float = field(default_factory=time.time)
    finished_at: float = 0.0
    duration_s:  float = 0.0

    # WAF
    waf_detected:    Optional[str] = None
    evasion_applied: Optional[str] = None

    # DBMS (auto-detected during scan)
    dbms_detected: Optional[str] = None

    # Stats
    crawled_urls:  int = 0
    params_tested: int = 0
    requests_sent: int = 0

    # Findings
    error_based:   List[ErrorBasedFinding] = field(default_factory=list)
    boolean_based: List[BooleanFinding]    = field(default_factory=list)
    time_based:    List[TimeFinding]       = field(default_factory=list)
    union_based:   List[UnionFinding]      = field(default_factory=list)
    oob:           List[OOBFinding]        = field(default_factory=list)
    stacked:       List[StackedFinding]    = field(default_factory=list)
    extracted:     List[ExtractionFinding] = field(default_factory=list)

    log:    List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    # --- Append helpers -------------------------------------------------------

    def _append(self, attr: str, finding: Any) -> None:
        with self._lock:
            getattr(self, attr).append(finding)

    def append_error_based(self, f)   -> None: self._append("error_based", f)
    def append_boolean(self, f)       -> None: self._append("boolean_based", f)
    def append_time(self, f)          -> None: self._append("time_based", f)
    def append_union(self, f)         -> None: self._append("union_based", f)
    def append_oob(self, f)           -> None: self._append("oob", f)
    def append_stacked(self, f)       -> None: self._append("stacked", f)
    def append_extraction(self, f)    -> None:
        with self._lock:
            # Deduplicate: skip if we already have this (param, expr) pair
            for existing in self.extracted:
                if existing.parameter == f.parameter and existing.expr == f.expr:
                    return
            self.extracted.append(f)
    def append_error(self, msg: str)  -> None: self._append("errors", msg)
    def append_log(self, msg: str)    -> None: self._append("log", msg)

    # --- Computed properties --------------------------------------------------

    def finish(self) -> "ScanResult":
        self.finished_at = time.time()
        self.duration_s  = round(self.finished_at - self.started_at, 2)
        return self

    @property
    def total_findings(self) -> int:
        return sum(len(getattr(self, attr)) for attr, _ in _FINDING_LISTS)

    @property
    def success(self) -> bool:
        return not bool(self.errors) or self.total_findings > 0

    def to_dict(self) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        for attr, ftype in _FINDING_LISTS:
            for item in getattr(self, attr):
                d = dataclasses.asdict(item)
                d["type"] = ftype.value
                findings.append(d)

        return {
            "success":         self.success,
            "target":          self.target,
            "duration_s":      self.duration_s,
            "waf_detected":    self.waf_detected,
            "evasion_applied": self.evasion_applied,
            "dbms_detected":   self.dbms_detected,
            "crawled_urls":    self.crawled_urls,
            "params_tested":   self.params_tested,
            "requests_sent":   self.requests_sent,
            "total_findings":  self.total_findings,
            "findings":        findings,
            "errors":          self.errors,
            "log":             self.log,
        }
