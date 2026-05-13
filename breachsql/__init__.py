# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — context-aware SQL injection scanner.

Quick start:

    from breachsql import scan, ScanOptions

    result = scan("https://target.com/search?q=test")
    print(result.total_findings)

    opts = ScanOptions(level=2, crawl=True, dbms="mysql")
    result = scan("https://target.com/search?q=test", opts)
"""

from breachsql.engine import scan, ScanOptions
from breachsql.engine.reporter import (
    ScanResult,
    ErrorBasedFinding,
    BooleanFinding,
    TimeFinding,
    UnionFinding,
    OOBFinding,
    FindingType,
)

__version__ = "0.1.1"

BANNER = r"""
  ____                      _      ____   ___  _
 | __ ) _ __ ___  __ _  ___| |__  / ___| / _ \| |
 |  _ \| '__/ _ \/ _` |/ __| '_ \ \___ \| | | | |
 | |_) | | |  __/ (_| | (__| | | | ___) | |_| | |___
 |____/|_|  \___|\__,_|\___|_| |_||____/ \__\_\_____|

  Every query has a crack.
  SQL Injection Engine — CommonHuman-Lab
"""

__all__ = [
    "__version__",
    "scan",
    "ScanOptions",
    "ScanResult",
    "ErrorBasedFinding",
    "BooleanFinding",
    "TimeFinding",
    "UnionFinding",
    "OOBFinding",
    "FindingType",
]
