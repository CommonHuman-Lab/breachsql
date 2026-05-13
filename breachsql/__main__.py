# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — __main__.py
CLI entry point.

Usage:
    python -m breachsql -u https://target.com/search?q=test
    breachsql -u https://target.com/search?q=test
"""

from __future__ import annotations

import json
import os
import sys

_HERE   = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _p in (_PARENT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from breachsql import BANNER
from breachsql.engine import scan, ScanOptions
from breachsql.engine.log import get_logger
from breachsql._cli.args import build_parser, interactive_prompts
from breachsql._cli.summary import print_summary
from commonhuman_cli.colour import BOLD, CYAN
from commonhuman_cli.logging import setup_logging
from commonhuman_cli.entrypoint import (
    load_url_list, compile_exclude_patterns, parse_headers, validate_timeout,
)

_cli_logger = get_logger("breachsql")


def _split_param_list(val) -> list[str]:
    """Accept either a list (from interactive mode) or a comma-separated string."""
    if isinstance(val, list):
        return [p.strip() for p in val if str(p).strip()]
    return [p.strip() for p in str(val).split(",") if p.strip()]


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    setup_logging(verbose=args.verbose, quiet=args.quiet or args.json_output, logger_name="breachsql")

    # Collect target URLs
    urls: list[str] = []
    if args.url:
        urls.append(args.url)
    if args.url_list:
        urls.extend(load_url_list(args.url_list))

    # No URL supplied → interactive mode
    if not urls:
        args = interactive_prompts()
        urls = [args.url]
    elif not args.json_output:
        print(CYAN(BANNER))

    validate_timeout(args.timeout)

    exclude_patterns = compile_exclude_patterns(args.exclude)
    headers          = parse_headers(args.header)

    opts = ScanOptions(
        crawl=args.crawl,
        data=args.data,
        headers=headers,
        cookies=args.cookie,
        proxy=args.proxy,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        level=args.level,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        output=args.output,
        exclude_patterns=exclude_patterns,
        dbms=args.dbms,
        technique=args.technique,
        oob_callback=args.oob,
        time_threshold=args.time_threshold,
        risk=args.risk,
        second_url=getattr(args, "second_url", ""),
        path_params=_split_param_list(getattr(args, "path_params", "")),
        cookie_params=_split_param_list(getattr(args, "cookie_params", "")),
        header_params=_split_param_list(getattr(args, "header_params", "")),
    )

    all_results = []
    any_findings = False

    for target_url in urls:
        if any(p.search(target_url) for p in exclude_patterns):
            _cli_logger.info("Skipping excluded URL: %s", target_url)
            continue

        if not args.json_output and not args.quiet:
            print(BOLD(f"[*] Target    : {target_url}"))
            print(BOLD(f"[*] Level     : {args.level}  Threads: {args.threads}  Crawl: {args.crawl}"))
            print(BOLD(f"[*] DBMS hint : {args.dbms}  Techniques: {args.technique}  Risk: {args.risk}"))
            print()

        result = scan(target_url, opts)
        all_results.append(result)
        if result.total_findings > 0:
            any_findings = True

        if args.json_output:
            print(json.dumps(result.to_dict(), indent=2))
            continue

        print_summary(result)

    if args.json_output:
        sys.exit(0 if not any_findings else 1)

    sys.exit(1 if any_findings else 0)


if __name__ == "__main__":
    main()
