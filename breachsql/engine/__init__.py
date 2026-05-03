# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — engine/__init__.py
Public API surface for the BreachSQL engine.
"""

from .reporter import (
    ErrorBasedFinding,
    BooleanFinding,
    TimeFinding,
    UnionFinding,
    OOBFinding,
    StackedFinding,
    FindingType,
    ScanResult,
)
from .scanner import ScanOptions, scan

__all__ = [
    "scan",
    "ScanOptions",
    "ScanResult",
    "FindingType",
    "ErrorBasedFinding",
    "BooleanFinding",
    "TimeFinding",
    "UnionFinding",
    "OOBFinding",
    "StackedFinding",
]
