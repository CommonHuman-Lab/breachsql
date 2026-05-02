# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""BreachSQL — engine/log.py — logging setup and custom FINDING level."""

from __future__ import annotations

import logging

__all__ = ["FINDING", "get_logger", "ScanResultHandler"]

# Custom level for confirmed/detected findings — sits between INFO (20) and WARNING (30).
FINDING = 25
logging.addLevelName(FINDING, "FINDING")


class StingLogger(logging.Logger):
    """Logger subclass that adds a .finding() convenience method."""

    def finding(self, msg: str, *args, **kwargs) -> None:
        if self.isEnabledFor(FINDING):
            self._log(FINDING, msg, args, **kwargs)


# Must be called before any logger is first retrieved so that all loggers
# in the "breachsql.*" hierarchy are StingLogger instances.
logging.setLoggerClass(StingLogger)


def get_logger(name: str) -> StingLogger:
    """Return (or create) a StingLogger for *name*."""
    return logging.getLogger(name)  # type: ignore[return-value]


class ScanResultHandler(logging.Handler):
    """Appends formatted log messages to a ScanResult.log list."""

    def __init__(self, result) -> None:
        super().__init__()
        self._result = result

    def emit(self, record: logging.LogRecord) -> None:
        self._result.append_log(self.format(record))
