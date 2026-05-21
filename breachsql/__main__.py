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

import copy
import dataclasses
import csv
import json
import os
import re
import sys
import urllib.parse as _up
from datetime import datetime

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

_AUTH_PATH_RE       = re.compile(r'/(login|signin|authenticate|session|token)\b', re.IGNORECASE)
_AUTH_SYNTH_BODY    = '{"email":"test@test.com","password":"test","username":"test"}'


def _split_param_list(val) -> list[str]:
    """Accept either a list (from interactive mode) or a comma-separated string."""
    if isinstance(val, list):
        return [p.strip() for p in val if str(p).strip()]
    return [p.strip() for p in str(val).split(",") if p.strip()]


def _safe_target_name(url: str) -> str:
    """Build a filesystem-safe target name for output files."""
    parsed = _up.urlparse(url)
    base = f"{parsed.netloc}{parsed.path}".strip() or "unknown"
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("_")
    return cleaned or "unknown"


def _build_readable_dump_text(target: str, extracted: list[dict]) -> str:
    """Build one human-readable per-table dump text from extracted entries."""
    table_map = _extract_structured_tables(extracted)
    lines: list[str] = []
    lines.append(f"Target: {target}")
    lines.append("")
    tables = list(table_map.keys())
    if not tables:
        lines.append("No structured table/column/row dump entries detected.")
        lines.append("")
        lines.append("Raw extracted values:")
        if not extracted:
            lines.append("(none)")
        else:
            for item in extracted:
                expr = str(item.get("expr", "")).strip()
                value = str(item.get("value", "")).strip()
                lines.append(f"- expr: {expr}")
                lines.append(f"  value: {value}")
        return "\n".join(lines) + "\n"

    for tbl in tables:
        data = table_map.get(tbl, {"columns": [], "rows": []})
        cols = data.get("columns", []) or []
        rows = data.get("rows", []) or []
        if not cols and rows:
            cols = [f"col_{i+1}" for i in range(max(len(r) for r in rows))]

        lines.append(f"Table: {tbl}")
        if rows:
            lines.append(f"[{len(rows)} entries]")
            matrix: list[list[str]] = [cols] + rows
            col_count = max(len(r) for r in matrix)
            widths = [0] * col_count
            for r in matrix:
                for i in range(col_count):
                    cell = r[i] if i < len(r) else ""
                    widths[i] = max(widths[i], len(str(cell)))
            sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

            def fmt_row(r: list[str]) -> str:
                cells = []
                for i in range(col_count):
                    cell = r[i] if i < len(r) else ""
                    cells.append(f" {cell.ljust(widths[i])} ")
                return "|" + "|".join(cells) + "|"

            lines.append(sep)
            lines.append(fmt_row(cols))
            lines.append(sep)
            for r in rows:
                lines.append(fmt_row(r))
            lines.append(sep)
        else:
            lines.append("Rows: (not extracted)")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _extract_structured_tables(extracted: list[dict]) -> dict[str, dict]:
    """Infer table -> columns/rows from extracted expressions/values."""
    table_map: dict[str, dict] = {}

    def _get_tbl(name: str) -> dict:
        table_map.setdefault(name, {"columns": [], "rows": []})
        return table_map[name]

    _meta_markers = (
        "information_schema.",
        "sqlite_master",
        "pragma_table_info(",
        "all_tab_columns",
    )

    for item in extracted:
        expr = str(item.get("expr", ""))
        value = str(item.get("value", ""))
        expr_l = expr.lower()

        # Skip schema/metadata extraction entries.
        if any(m in expr_l for m in _meta_markers):
            continue

        m_cols = re.search(r"pragma_table_info\('([^']+)'\)", expr, flags=re.IGNORECASE)
        if not m_cols:
            m_cols = re.search(r"table_name='([^']+)'", expr, flags=re.IGNORECASE)
        if not m_cols:
            m_cols = re.search(r"TABLE_NAME='([^']+)'", expr, flags=re.IGNORECASE)
        if not m_cols:
            m_cols = re.search(r"table_name=UPPER\('([^']+)'\)", expr, flags=re.IGNORECASE)
        if m_cols:
            tbl = m_cols.group(1)
            cols = [c.strip() for c in value.split(",") if c.strip()]
            _get_tbl(tbl)["columns"] = cols
            continue

        m_dump = re.search(
            r'FROM\s+["`\[]?([A-Za-z0-9_.-]+)["`\]]?\s+(?:LIMIT|WHERE|GROUP|ORDER|TOP)',
            expr,
            flags=re.IGNORECASE,
        )
        if m_dump and ("GROUP_CONCAT" in expr or "string_agg" in expr or "STRING_AGG" in expr or "LISTAGG" in expr):
            tbl = m_dump.group(1)
            if tbl.lower() in ("information_schema", "sqlite_master"):
                continue
            rows = [r for r in value.split("|") if r]
            parsed_rows = [[cell.strip() for cell in row.split(",")] for row in rows]
            _get_tbl(tbl)["rows"] = parsed_rows
            continue

    return table_map


def _combine_results(urls: list[str], all_results: list) -> object:
    """Return a combined JSON-serialisable view across all scan results."""
    from .engine.reporter import ScanResult

    if len(all_results) == 1:
        return all_results[0].to_dict()

    combined = ScanResult(target=urls[0] if urls else "")
    combined.duration_s      = sum(r.duration_s for r in all_results)
    combined.requests_sent   = sum(r.requests_sent for r in all_results)
    combined.crawled_urls    = sum(r.crawled_urls for r in all_results)
    combined.params_tested   = sum(r.params_tested for r in all_results)
    combined.waf_detected    = next((r.waf_detected for r in all_results if r.waf_detected), None)
    combined.evasion_applied = next((r.evasion_applied for r in all_results if r.evasion_applied), None)
    combined.dbms_detected   = next((r.dbms_detected for r in all_results if r.dbms_detected), None)
    for r in all_results:
        combined.error_based.extend(r.error_based)
        combined.boolean_based.extend(r.boolean_based)
        combined.time_based.extend(r.time_based)
        combined.union_based.extend(r.union_based)
        combined.oob.extend(r.oob)
        combined.stacked.extend(r.stacked)
        combined.extracted.extend(r.extracted)
        combined.errors.extend(r.errors)
    combined.target = f"{urls[0]} (+{len(urls)-1} more)" if len(urls) > 1 else (urls[0] if urls else "")

    return {
        "mode": "multi-target",
        "targets": [r.to_dict() for r in all_results],
        "combined": combined.to_dict(),
    }


def _build_combined_result(urls: list[str], all_results: list):
    """Build a combined ScanResult for human-readable multi-target summary."""
    from .engine.reporter import ScanResult

    combined = ScanResult(target=urls[0] if urls else "")
    combined.duration_s      = sum(r.duration_s for r in all_results)
    combined.requests_sent   = sum(r.requests_sent for r in all_results)
    combined.crawled_urls    = sum(r.crawled_urls for r in all_results)
    combined.params_tested   = sum(r.params_tested for r in all_results)
    combined.waf_detected    = next((r.waf_detected for r in all_results if r.waf_detected), None)
    combined.evasion_applied = next((r.evasion_applied for r in all_results if r.evasion_applied), None)
    combined.dbms_detected   = next((r.dbms_detected for r in all_results if r.dbms_detected), None)
    for r in all_results:
        combined.error_based.extend(r.error_based)
        combined.boolean_based.extend(r.boolean_based)
        combined.time_based.extend(r.time_based)
        combined.union_based.extend(r.union_based)
        combined.oob.extend(r.oob)
        combined.stacked.extend(r.stacked)
        combined.extracted.extend(r.extracted)
        combined.errors.extend(r.errors)
    combined.target = f"{urls[0]} (+{len(urls)-1} more)" if len(urls) > 1 else (urls[0] if urls else "")
    return combined


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

    # Form login
    if getattr(args, "login_url", "") and getattr(args, "login_user", ""):
        from commonhuman_core.auth import form_login as _form_login
        if not args.quiet and not args.json_output:
            print(f"[*] Authenticating via {args.login_url} ...")
        auth = _form_login(
            login_url=args.login_url,
            username=args.login_user,
            password=getattr(args, "login_pass", ""),
            username_field=getattr(args, "login_user_field", "username"),
            password_field=getattr(args, "login_pass_field", "password"),
        )
        if auth.cookies and not args.cookie:
            args.cookie = auth.cookies
        headers.update(auth.headers)

    # OpenAPI spec import
    if getattr(args, "openapi", ""):
        from commonhuman_core.openapi import load_openapi as _load_openapi
        if not args.quiet and not args.json_output:
            print(f"[*] Loading OpenAPI spec from {args.openapi} ...")
        api_eps = _load_openapi(args.openapi, base_url=getattr(args, "base_url", ""))
        seen_oa = set(urls)
        for ep in api_eps:
            if ep.url not in seen_oa:
                urls.append(ep.url)
                seen_oa.add(ep.url)
        if not args.quiet and not args.json_output:
            print(f"[*] OpenAPI: {len(api_eps)} endpoint(s) added")

    # Per-URL POST body overrides: populated by JS discovery for auth endpoints.
    url_data_overrides: dict[str, str] = {}

    # JS API discovery — parse SPA bundles for REST/API endpoints
    if (args.crawl or getattr(args, "browser_crawl", False)) and urls:
        from commonhuman_core.js_api_discover import js_api_discover as _js_discover
        seed = urls[0]
        if not args.quiet and not args.json_output:
            print(f"[*] JS API discovery on {seed} ...")
        seen_js = set(urls)
        js_found = _js_discover(seed)
        new_js: list[str] = []
        for _method, js_url, _tmpl in js_found:
            if js_url not in seen_js:
                seen_js.add(js_url)
                new_js.append(js_url)
                urls.append(js_url)
                # Synthesise a JSON body for discovered POST auth endpoints so
                # the scanner can build injectable surfaces (email/password fields).
                if _method == "POST" and _AUTH_PATH_RE.search(_up.urlparse(js_url).path):
                    url_data_overrides[js_url] = _AUTH_SYNTH_BODY
        if not args.quiet and not args.json_output:
            print(f"[*] JS discovery: {len(new_js)} endpoint(s) found")

    # Browser crawl — headless JS endpoint discovery
    if getattr(args, "browser_crawl", False) and urls:
        from commonhuman_core.browser_crawler import browser_crawl as _browser_crawl
        seed = urls[0]
        if not args.quiet and not args.json_output:
            print(f"[*] Browser-crawling {seed} ...")
        bc_found = _browser_crawl(
            start_url=seed,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            cookies=args.cookie or "",
        )
        seen_bc = set(urls)
        new_bc  = [u for u in bc_found if u not in seen_bc]
        urls.extend(new_bc)
        if not args.quiet and not args.json_output:
            print(f"[*] Browser crawl: {len(new_bc)} additional endpoint(s) queued")

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
        output="",
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
        exploit=(getattr(args, "exploit", False)
                 or bool(getattr(args, "dump", ""))
                 or bool(getattr(args, "dump_columns", ""))),
        dump=getattr(args, "dump", ""),
        dump_columns=getattr(args, "dump_columns", ""),
    )

    all_results = []
    any_findings = False
    multi = len(urls) > 1

    for target_url in urls:
        if any(p.search(target_url) for p in exclude_patterns):
            _cli_logger.info("Skipping excluded URL: %s", target_url)
            continue

        if not args.json_output and not args.quiet:
            if not multi:
                print(BOLD(f"[*] Target    : {target_url}"))
                print(BOLD(f"[*] Level     : {args.level}  Threads: {args.threads}  Crawl: {args.crawl}"))
                print(BOLD(f"[*] DBMS hint : {args.dbms}  Techniques: {args.technique}  Risk: {args.risk}"))
                print()

        _scan_opts = opts
        if target_url in url_data_overrides and not opts.data:
            _scan_opts = copy.copy(opts)
            _scan_opts.data = url_data_overrides[target_url]

        result = scan(target_url, _scan_opts)
        all_results.append(result)
        if result.total_findings > 0:
            any_findings = True

        if args.json_output:
            print(json.dumps(result.to_dict(), indent=2))
            continue

        if multi:
            # In multi-URL mode: only show a line when findings exist
            if result.total_findings > 0:
                print(f"  [+] {result.total_findings} finding(s) — {target_url}")
        else:
            print_summary(result)

    if not args.json_output and multi:
        combined = _build_combined_result(urls, all_results)
        print()
        print_summary(combined)

    if args.output and all_results:
        output_payload = _combine_results(urls, all_results)
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(output_payload, fh, indent=2)
        except OSError as exc:
            _cli_logger.error("Failed to write output file '%s': %s", args.output, exc)

    # Always persist extracted data (if present) under .venv/output with target-prefixed names.
    extracted_results = [r for r in all_results if getattr(r, "extracted", None)]
    if extracted_results:
        out_dir = os.path.join(sys.prefix, "output")
        try:
            os.makedirs(out_dir, exist_ok=True)
        except OSError as exc:
            _cli_logger.error("Failed to create output directory '%s': %s", out_dir, exc)
        else:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            for r in extracted_results:
                target_name = _safe_target_name(getattr(r, "target", ""))
                out_path = os.path.join(out_dir, f"target_{target_name}_{stamp}.json")
                payload = {
                    "target": r.target,
                    "dbms_detected": getattr(r, "dbms_detected", None),
                    "duration_s": getattr(r, "duration_s", 0.0),
                    "requests_sent": getattr(r, "requests_sent", 0),
                    "params_tested": getattr(r, "params_tested", 0),
                    "total_findings": getattr(r, "total_findings", 0),
                    "extracted": [dataclasses.asdict(e) for e in r.extracted],
                }
                try:
                    with open(out_path, "w", encoding="utf-8") as fh:
                        json.dump(payload, fh, indent=2)
                except OSError as exc:
                    _cli_logger.error("Failed to write extracted output file '%s': %s", out_path, exc)

                readable_text = _build_readable_dump_text(
                    target=r.target,
                    extracted=payload["extracted"],
                )
                readable_path = os.path.join(out_dir, f"target_{target_name}_{stamp}_dump.txt")
                try:
                    with open(readable_path, "w", encoding="utf-8") as fh:
                        fh.write(readable_text)
                except OSError as exc:
                    _cli_logger.error("Failed to write readable dump file '%s': %s", readable_path, exc)
                else:
                    if getattr(args, "dump_readable", False):
                        print(readable_text)

                # Also save consolidated CSV in long format for reliable parsing.
                # Columns: table,row_index,column,value
                csv_path = os.path.join(out_dir, f"target_{target_name}_{stamp}_dump.csv")
                table_map = _extract_structured_tables(payload["extracted"])
                try:
                    with open(csv_path, "w", encoding="utf-8", newline="") as fh:
                        w = csv.writer(fh)
                        w.writerow(["table", "row_index", "column", "value"])
                        for tbl, data in table_map.items():
                            cols = data.get("columns", []) or []
                            rows = data.get("rows", []) or []
                            for idx, row in enumerate(rows, start=1):
                                if cols:
                                    for c_i, cell in enumerate(row):
                                        col = cols[c_i] if c_i < len(cols) else f"col_{c_i + 1}"
                                        w.writerow([tbl, idx, col, cell])
                                else:
                                    for c_i, cell in enumerate(row):
                                        w.writerow([tbl, idx, f"col_{c_i + 1}", cell])
                except OSError as exc:
                    _cli_logger.error("Failed to write consolidated CSV dump file '%s': %s", csv_path, exc)

    if args.json_output:
        sys.exit(0 if not any_findings else 1)

    sys.exit(1 if any_findings else 0)


if __name__ == "__main__":
    main()
