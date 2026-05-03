# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — engine/http/reflection.py
XSS/input reflection probe helpers.

These were previously part of the Injector class but are unrelated to core
SQL injection HTTP transport and are therefore extracted here.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

from requests import Response

from .injector import Injector

_TAG_PROBE_TEMPLATES = [
    # Generic: any-tag URL attr  → discovers URL_ATTR / ATTR_DOUBLE
    '<img src="{marker}">',
    '<img src=x alt="{marker}">',
    # style attribute → discovers ATTR_DOUBLE (style= context)
    '<div style="{marker}">',
    # event handler → discovers EVENT_HANDLER
    '<img src=x onerror="{marker}">',
    # href → URL_ATTR
    '<a href="{marker}">x</a>',
    # script src → URL_ATTR on src of script
    '<script src="{marker}"></script>',
    # meta content → ATTR_DOUBLE
    '<meta name="x" content="{marker}">',
    # body with marker as inner content → HTML_BODY
    '<body>{marker}</body>',
    # body with marker in onload (event handler)
    '<body onload="{marker}">',
    # multiline prefix trick (for single-line regex filters)
    '\n<img src="{marker}">',
    '\n<script>var x="{marker}"</script>',
]


def probe_reflection(
    injector: Injector,
    url: str,
    param: str,
    marker: str,
    method: str = "GET",
    base_data: Optional[Dict[str, str]] = None,
) -> Tuple[bool, Response]:
    """
    Send a reflection probe for `marker` on `param`.

    Strategy:
    1. Try injecting the marker as a plain string first (catches most cases).
    2. If the plain probe returns a non-2xx status or no reflection, try
       embedding the marker inside tag attribute values.  This handles servers
       that validate the input must look like a specific HTML tag (e.g. the
       Google Firing Range /tags/* endpoints) and return 400 for plain text.

    Returns (reflected: bool, response).
    """
    from ..analysis.parser import is_reflected

    if method.upper() == "POST":
        resp = injector.inject_post(url, param, marker, base_data)
    else:
        resp = injector.inject_get(url, param, marker)

    if resp.status_code < 400 and is_reflected(resp.text, marker):
        return True, resp

    # --- Non-2xx body scanning -------------------------------------------
    # Some endpoints reflect the marker even in error responses.
    if is_reflected(resp.text, marker):
        return True, resp

    # --- Tag-wrapping fallback probes ------------------------------------
    for template in _TAG_PROBE_TEMPLATES:
        probe_value = template.replace("{marker}", marker)
        try:
            if method.upper() == "POST":
                r = injector.inject_post(url, param, probe_value, base_data)
            else:
                r = injector.inject_get(url, param, probe_value)
        except Exception:
            continue
        if is_reflected(r.text, marker):
            return True, r

    # Nothing reflected
    return False, resp


def probe_header_reflection(
    injector: Injector,
    url: str,
    header_name: str,
    marker: str,
) -> Tuple[bool, Response]:
    """Probe whether `marker` injected via `header_name` is reflected."""
    resp = injector.inject_header(url, header_name, marker)
    reflected = marker in resp.text
    return reflected, resp
