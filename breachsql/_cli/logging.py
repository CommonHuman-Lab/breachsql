# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
import logging
import traceback

from breachsql._cli.colour import GREEN, YELLOW, CYAN, DIM
from breachsql.engine.log import FINDING, get_logger


class _ColorHandler(logging.StreamHandler):
    """Writes log records to stdout with ANSI colour based on level."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
            if record.levelno >= logging.WARNING:
                print(YELLOW(f"[!] {msg}"))
            elif record.levelno == FINDING:
                print(GREEN(f"[+] {msg}"))
            elif record.levelno == logging.DEBUG:
                print(CYAN(f"[~] {msg}"))
            else:
                print(DIM(f"[*] {msg}"))
            if record.exc_info:
                traceback.print_exception(*record.exc_info)
            self.flush()
        except Exception:
            self.handleError(record)


def setup_logging(verbose: bool, quiet: bool) -> None:
    root = get_logger("breachsql")
    for h in root.handlers[:]:
        h.close()
        root.handlers.remove(h)
    root.propagate = False
    if quiet:
        root.setLevel(logging.ERROR)
        return
    handler = _ColorHandler()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.addHandler(handler)
