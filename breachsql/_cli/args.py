# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
from __future__ import annotations

import argparse
import sys

from breachsql._cli.colour import BOLD, CYAN, DIM, YELLOW, BANNER

try:
    from breachsql import __version__
except ImportError:
    __version__ = "0.1.0"


def _safe_int(val: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(int(val), hi))
    except (TypeError, ValueError):
        return default


def _prompt(label: str, default: str = "", hint: str = "") -> str:
    hint_str = f"  {DIM(hint)}" if hint else ""
    if default:
        display = f"{BOLD(label)} {DIM(f'[{default}]')}{hint_str}: "
    else:
        display = f"{BOLD(label)}{hint_str}: "
    try:
        val = input(display).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    return val if val else default


def _prompt_bool(label: str, default: bool = False) -> bool:
    default_str = "Y/n" if default else "y/N"
    display = f"{BOLD(label)} {DIM(f'[{default_str}]')}: "
    try:
        val = input(display).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)
    if not val:
        return default
    return val in ("y", "yes", "1", "true")


def _section(title: str) -> None:
    print()
    print(DIM("  ─── " + title + " " + "─" * max(0, 40 - len(title))))


def interactive_prompts() -> argparse.Namespace:
    """Walk the user through all scan options interactively."""
    print(CYAN(BANNER))
    print(DIM("  No arguments supplied — entering interactive mode."))
    print(DIM("  Press Enter to accept defaults. Ctrl+C to exit.\n"))

    _section("Target")
    url = ""
    while not url:
        url = _prompt("  Target URL", hint="e.g. https://target.com/search?q=test")
        if not url:
            print(YELLOW("  [!] URL is required."))
        elif not url.startswith(("http://", "https://")):
            print(YELLOW("  [!] URL must start with http:// or https://"))
            url = ""

    _section("Authentication  (optional)")
    cookie = _prompt("  Cookies", hint="name=val; name2=val2")
    headers_raw: list[str] = []
    while True:
        h = _prompt("  Header", hint="KEY:VALUE  (blank to finish)")
        if not h:
            break
        headers_raw.append(h)

    _section("Request")
    data  = _prompt("  POST body", hint="form-encoded or JSON  (blank = GET)")
    proxy = _prompt("  Proxy", hint="http://127.0.0.1:8080")

    _section("SQLi options")
    dbms       = _prompt("  Target DBMS", default="auto",
                         hint="mysql | mssql | postgres | sqlite | auto")
    technique  = _prompt("  Techniques", default="EBTUO",
                         hint="E=error B=bool T=time U=union O=oob  (e.g. EBT)")
    oob        = _prompt("  OOB callback URL", hint="https://your.interactsh.io/x  (blank to skip)")
    time_thr   = _prompt("  Time threshold", default="4", hint="seconds to flag time-based hit")
    risk_str   = _prompt("  Risk level", default="1", hint="1=safe 2=moderate 3=aggressive")

    _section("Scan options")
    level_str   = _prompt("  Scan level",  default="1", hint="1=fast  2=thorough  3=deep")
    threads_str = _prompt("  Threads",     default="5")
    timeout_str = _prompt("  Timeout",     default="15", hint="seconds per request")

    crawl = _prompt_bool("  Enable crawler", default=False)
    if crawl:
        max_pages_str = _prompt("  Max pages", default="50")
        max_depth_str = _prompt("  Max depth", default="3")
    else:
        max_pages_str = "50"
        max_depth_str = "3"
    print()

    return argparse.Namespace(
        url=url,
        url_list="",
        crawl=crawl,
        data=data,
        header=headers_raw,
        cookie=cookie,
        proxy=proxy,
        threads=_safe_int(threads_str, 5, 1, 20),
        timeout=_safe_int(timeout_str, 15, 5, 120),
        delay=0.0,
        level=_safe_int(level_str, 1, 1, 3),
        max_pages=_safe_int(max_pages_str, 50, 1, 500),
        max_depth=_safe_int(max_depth_str, 3, 1, 10),
        exclude=[],
        output="",
        json_output=False,
        quiet=False,
        verbose=False,
        dbms=dbms,
        technique=technique.upper(),
        oob=oob,
        time_threshold=_safe_int(time_thr, 4, 1, 30),
        risk=_safe_int(risk_str, 1, 1, 3),
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="breachsql",
        description="BreachSQL — context-aware SQL injection scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")

    # --- Target ---
    p.add_argument("-u", "--url",      default="",  help="Target URL")
    p.add_argument("-L", "--url-list", default="",  metavar="FILE",
                   help="File of target URLs (one per line)")

    # --- Request ---
    p.add_argument("--crawl",        action="store_true", help="Enable BFS crawler")
    p.add_argument("-d", "--data",   default="",  help="POST body")
    p.add_argument("-H", "--header", action="append", default=[], metavar="KEY:VALUE",
                   help="Custom header (repeatable)")
    p.add_argument("-c", "--cookie", default="",  help="Cookie string")
    p.add_argument("--proxy",        default="",  help="HTTP proxy URL")
    p.add_argument("-t", "--threads", type=int, default=5,
                   help="Worker threads 1-20 (default 5)")
    p.add_argument("--timeout",      type=int, default=15,
                   help="Request timeout seconds 5-120 (default 15)")
    p.add_argument("--delay",        type=float, default=0.0,
                   help="Seconds between requests (default 0)")

    # --- Scan depth ---
    p.add_argument("--level",     type=int, default=1, choices=[1, 2, 3],
                   help="Scan depth: 1=fast 2=thorough 3=deep (default 1)")
    p.add_argument("--max-pages", type=int, default=50,
                   help="Max pages to crawl (default 50)")
    p.add_argument("--max-depth", type=int, default=3,
                   help="Max crawl depth (default 3)")
    p.add_argument("--exclude",   action="append", default=[], metavar="PATTERN",
                   help="Regex pattern of URLs to skip (repeatable)")

    # --- SQLi-specific ---
    p.add_argument("--dbms",      default="auto",
                   choices=["auto", "mysql", "mssql", "postgres", "sqlite"],
                   help="Target DBMS hint (default: auto-detect)")
    p.add_argument("--technique", default="EBTUO", metavar="TECHNIQUES",
                   help="Techniques to use: E=error B=bool T=time U=union O=oob (default: EBTUO)")
    p.add_argument("--oob",       default="", metavar="URL",
                   help="Out-of-band callback URL for OOB detection")
    p.add_argument("--time-threshold", type=int, default=4, dest="time_threshold",
                   help="Seconds delta to flag time-based SQLi (default 4)")
    p.add_argument("--risk",      type=int, default=1, choices=[1, 2, 3],
                   help="Risk level: 1=safe 2=moderate 3=aggressive (default 1)")

    # --- Output ---
    p.add_argument("-o", "--output", default="", metavar="FILE",
                   help="Write JSON results to this file")
    p.add_argument("--json",     action="store_true", dest="json_output",
                   help="Output raw JSON")
    p.add_argument("-q", "--quiet",   action="store_true",
                   help="Suppress live log output")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show all checks including clean ones")

    return p
