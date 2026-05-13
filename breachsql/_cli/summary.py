# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
from __future__ import annotations

import urllib.parse as _up

from commonhuman_cli.colour import BOLD, CYAN, DIM, GREEN, RED, YELLOW


def _proof_url(url: str, param: str, payload: str, original: str = "1") -> str:
    """
    Build a proof-of-concept URL by injecting *payload* into *param*.

    The payload is appended to the original param value (matching how the
    scanner injects it) so the link reproduces the exact request that
    triggered the finding.  The result is percent-encoded so it is safe
    to paste into a browser address bar or terminal.
    """
    try:
        parsed   = _up.urlparse(url)
        qs       = _up.parse_qs(parsed.query, keep_blank_values=True)
        orig_val = qs.get(param, [original])[0]
        injected = orig_val + payload
        qs[param] = [injected]
        new_query = _up.urlencode(qs, doseq=True)
        return _up.urlunparse(parsed._replace(query=new_query))
    except Exception:
        return ""


def print_summary(result) -> None:
    print()
    print(BOLD("=" * 60))
    print(BOLD("  BreachSQL — Scan Summary"))
    print(BOLD("=" * 60))
    print(f"  Target        : {result.target}")
    print(f"  Duration      : {result.duration_s}s")
    print(f"  Requests sent : {result.requests_sent}")
    print(f"  URLs crawled  : {result.crawled_urls}")
    print(f"  Params tested : {result.params_tested}")
    print(f"  WAF detected  : {result.waf_detected or 'None'}")
    print(f"  Evasion used  : {result.evasion_applied or 'None'}")
    print(f"  DBMS detected : {result.dbms_detected or 'Unknown'}")
    print()

    if result.total_findings == 0:
        print(DIM("  No findings."))
    else:
        print(GREEN(f"  Total findings: {result.total_findings}"))
        print()
        i = 1

        for f in result.error_based:
            print(f"  {i}. {RED('[ERROR-BASED SQLi]')} Confirmed")
            print(f"     Param   : {f.parameter}")
            print(f"     URL     : {f.url}")
            print(f"     Method  : {f.method}")
            print(f"     DBMS    : {f.dbms}")
            print(f"     Payload : {f.payload}")
            if f.evidence:
                print(f"     Evidence: {DIM(f.evidence[:120])}")
            if f.method.upper() == "GET":
                print(f"     Proof   : {CYAN(_proof_url(f.url, f.parameter, f.payload))}")
            print()
            i += 1

        for f in result.boolean_based:
            status = GREEN("[CONFIRMED]") if f.confirmed else YELLOW("[LIKELY]")
            print(f"  {i}. {status} {YELLOW('Boolean-based SQLi')}")
            print(f"     Param      : {f.parameter}")
            print(f"     URL        : {f.url}")
            print(f"     Method     : {f.method}")
            print(f"     True payload  : {f.payload_true}")
            print(f"     False payload : {f.payload_false}")
            print(f"     Diff score : {f.diff_score:.2f}")
            if f.method.upper() == "GET":
                print(f"     Proof (true) : {CYAN(_proof_url(f.url, f.parameter, f.payload_true))}")
                print(f"     Proof (false): {CYAN(_proof_url(f.url, f.parameter, f.payload_false))}")
            print()
            i += 1

        for f in result.time_based:
            print(f"  {i}. {CYAN('[TIME-BASED BLIND SQLi]')}")
            print(f"     Param     : {f.parameter}")
            print(f"     URL       : {f.url}")
            print(f"     Method    : {f.method}")
            print(f"     DBMS hint : {f.dbms}")
            print(f"     Payload   : {f.payload}")
            print(f"     Delay     : {f.observed_delay:.2f}s  (threshold: {f.threshold}s)")
            if f.method.upper() == "GET":
                print(f"     Proof   : {CYAN(_proof_url(f.url, f.parameter, f.payload))}")
            print()
            i += 1

        for f in result.union_based:
            print(f"  {i}. {RED('[UNION-BASED SQLi]')} Confirmed")
            print(f"     Param    : {f.parameter}")
            print(f"     URL      : {f.url}")
            print(f"     Method   : {f.method}")
            print(f"     Columns  : {f.column_count}")
            print(f"     Payload  : {f.payload}")
            if f.extracted:
                print(f"     Extracted: {DIM(f.extracted[:120])}")
            if f.method.upper() == "GET":
                print(f"     Proof   : {CYAN(_proof_url(f.url, f.parameter, f.payload))}")
            print()
            i += 1

        for f in result.oob:
            print(f"  {i}. {CYAN('[OOB SQLi]')} Payload injected")
            print(f"     Param    : {f.parameter}")
            print(f"     URL      : {f.url}")
            print(f"     Callback : {f.callback_url}")
            print(f"     Payload  : {f.payload}")
            if f.method.upper() == "GET":
                print(f"     Proof   : {CYAN(_proof_url(f.url, f.parameter, f.payload))}")
            print()
            i += 1

        for f in result.stacked:
            print(f"  {i}. {RED('[STACKED QUERY SQLi]')} Confirmed")
            print(f"     Param   : {f.parameter}")
            print(f"     URL     : {f.url}")
            print(f"     Method  : {f.method}")
            print(f"     DBMS    : {f.dbms}")
            print(f"     Payload : {f.payload}")
            if f.evidence:
                print(f"     Evidence: {DIM(f.evidence[:120])}")
            if f.method.upper() == "GET":
                print(f"     Proof   : {CYAN(_proof_url(f.url, f.parameter, f.payload))}")
            print()
            i += 1

        if result.extracted:
            print(f"  {GREEN('─' * 56)}")
            print(f"  {GREEN(BOLD('  Extracted Data'))}")
            print(f"  {GREEN('─' * 56)}")
            for f in result.extracted:
                print(f"  {i}. {GREEN('[EXTRACTED]')} via {f.mode}-blind")
                print(f"     Param : {f.parameter}")
                print(f"     URL   : {f.url}")
                print(f"     Expr  : {DIM(f.expr)}")
                print(f"     Value : {BOLD(f.value)}")
                print()
                i += 1

    if result.errors:
        print(RED("  Errors:"))
        for e in result.errors:
            print(f"    - {e}")

    print(BOLD("=" * 60))
