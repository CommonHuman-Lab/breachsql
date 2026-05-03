# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — engine/injector.py
HTTP engine: session management, request helpers, parameter injection.

All HTTP communication in BreachSQL goes through this module so that
proxy, timeout, headers, cookies, and request counting are centralised.
"""

from __future__ import annotations

import json
import time
import urllib.parse as up
from typing import Any, Dict, List, Optional, Tuple

import urllib3
import requests
from requests import Response
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_UA = (
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
  "AppleWebKit/537.36 (KHTML, like Gecko) "
  "Chrome/124.0.0.0 Safari/537.36"
)


class Injector:
  """
  Thin wrapper around requests.Session with:
  - configurable proxy, headers, cookies
  - automatic retry on transient errors
  - request counter (exposed on scan result)
  - GET/POST helpers for XSS injection
  """

  def __init__(
    self,
    timeout:   int = 15,
    proxy:     Optional[str] = None,
    headers:   Optional[Dict[str, str]] = None,
    cookies:   Optional[str] = None,
    verify_ssl: bool = False,
    delay:     float = 0.0,
  ) -> None:
    self.timeout     = timeout
    self.request_count = 0
    self.delay       = max(0.0, delay)

    self._session = requests.Session()
    self._session.verify = verify_ssl

    # Retry strategy: 2 retries on connection/read errors, no retry on 4xx/5xx
    retry = Retry(
      total=2,
      backoff_factor=0.3,
      status_forcelist=(),
      allowed_methods=["GET", "POST", "HEAD"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    self._session.mount("http://",  adapter)
    self._session.mount("https://", adapter)

    # Default headers
    base_headers: Dict[str, str] = {"User-Agent": DEFAULT_UA}
    if headers:
      base_headers.update(headers)
    self._session.headers.update(base_headers)

    # Cookies
    if cookies:
      self._session.cookies.update(_parse_cookie_string(cookies))

    # Proxy
    if proxy:
      self._session.proxies = {"http": proxy, "https": proxy}

  # -------------------------------------------------------------------------
  # Low-level request helpers
  # -------------------------------------------------------------------------

  def get(self, url: str, params: Optional[Dict[str, str]] = None, **kwargs) -> Response:
    if self.delay:
      time.sleep(self.delay)
    self.request_count += 1
    return self._session.get(url, params=params, timeout=self.timeout, **kwargs)

  def post(self, url: str, data: Optional[Dict[str, Any]] = None,
           json_body: Optional[Any] = None, **kwargs) -> Response:
    if self.delay:
      time.sleep(self.delay)
    self.request_count += 1
    return self._session.post(
      url, data=data, json=json_body, timeout=self.timeout, **kwargs
    )

  def head(self, url: str, **kwargs) -> Response:
    self.request_count += 1
    return self._session.head(url, timeout=self.timeout, allow_redirects=True, **kwargs)

  # -------------------------------------------------------------------------
  # XSS injection helpers
  # -------------------------------------------------------------------------

  def inject_get(self, url: str, param: str, payload: str) -> Response:
    """Inject `payload` as the value of `param` in the URL query string."""
    parsed  = up.urlparse(url)
    qs      = up.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_qs  = up.urlencode(qs, doseq=True)
    target  = up.urlunparse(parsed._replace(query=new_qs))
    return self.get(target)

  def inject_post(self, url: str, param: str, payload: str,
                  base_data: Optional[Dict[str, str]] = None) -> Response:
    """Inject `payload` as the value of `param` in a POST body."""
    data = dict(base_data or {})
    data[param] = payload
    return self.post(url, data=data)

  def inject_post_json(self, url: str, param: str, payload: str,
                       base_data: Optional[Dict[str, Any]] = None) -> Response:
    """Inject into a JSON POST body."""
    body = dict(base_data or {})
    body[param] = payload
    return self.post(url, json_body=body)

  def inject_path(self, url: str, segment_index: int, payload: str) -> Response:
    """Inject `payload` into a URL path segment by position index.

    The original path segment at *segment_index* (0-based, after splitting on
    ``/``) is replaced with ``payload``.  Use this for REST-style path
    parameters such as ``/rest/track-order/:id``.
    """
    parsed = up.urlparse(url)
    parts  = parsed.path.split("/")  # e.g. ['', 'rest', 'track-order', '123']
    if 0 <= segment_index < len(parts):
      parts[segment_index] = up.quote(str(payload), safe="")
    new_path = "/".join(parts)
    target   = up.urlunparse(parsed._replace(path=new_path))
    return self.get(target)

  def inject_cookie(self, url: str, cookie_name: str, payload: str) -> Response:
    """Inject `payload` as the value of `cookie_name`, overriding for this request."""
    return self.get(url, cookies={cookie_name: payload})

  def inject_header(self, url: str, header_name: str, payload: str) -> Response:
    """Inject `payload` as the value of a custom HTTP request header."""
    return self.get(url, headers={header_name: payload})

  def probe_header_reflection(
    self, url: str, header_name: str, marker: str
  ) -> tuple[bool, Response]:
    """Probe whether `marker` injected via `header_name` is reflected."""
    resp = self.inject_header(url, header_name, marker)
    from ..analysis.parser import is_reflected
    return is_reflected(resp.text, marker), resp

  def probe_reflection(self, url: str, param: str, marker: str,
                       method: str = "GET",
                       base_data: Optional[Dict[str, str]] = None) -> Tuple[bool, Response]:
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
      resp = self.inject_post(url, param, marker, base_data)
    else:
      resp = self.inject_get(url, param, marker)

    if resp.status_code < 400 and is_reflected(resp.text, marker):
      return True, resp

    # --- Non-2xx body scanning -------------------------------------------
    # Some endpoints (e.g. /reflected/parameter/body/4xx) reflect the marker
    # even in error responses.  Accept any status code here.
    if is_reflected(resp.text, marker):
      return True, resp

    # --- Tag-wrapping fallback probes -----------------------------------
    # Try embedding the marker in positions that survive tag-based filters.
    # The templates cover: URL attr (src/href), generic double-quoted attr,
    # event handler, style attr, script src, meta content, and body content.
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
    for template in _TAG_PROBE_TEMPLATES:
      probe_value = template.replace("{marker}", marker)
      try:
        if method.upper() == "POST":
          r = self.inject_post(url, param, probe_value, base_data)
        else:
          r = self.inject_get(url, param, probe_value)
      except Exception:
        continue
      if is_reflected(r.text, marker):
        return True, r

    # Nothing reflected
    return False, resp

  # -------------------------------------------------------------------------
  # URL utilities
  # -------------------------------------------------------------------------

  @staticmethod
  def get_params(url: str) -> List[str]:
    """Return query parameter names from a URL."""
    parsed = up.urlparse(url)
    return list(up.parse_qs(parsed.query, keep_blank_values=True).keys())

  @staticmethod
  def get_base_url(url: str) -> str:
    """Return scheme + netloc only."""
    p = up.urlparse(url)
    return f"{p.scheme}://{p.netloc}"

  @staticmethod
  def same_origin(url_a: str, url_b: str) -> bool:
    """True if both URLs share the same scheme + netloc."""
    pa, pb = up.urlparse(url_a), up.urlparse(url_b)
    return pa.scheme == pb.scheme and pa.netloc == pb.netloc

  def close(self) -> None:
    self._session.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_cookie_string(cookies: str) -> Dict[str, str]:
  """Parse 'name=value; name2=value2' or JSON string."""
  cookies = cookies.strip()
  if cookies.startswith("{"):
    try:
      return json.loads(cookies)
    except Exception:
      pass
  result: Dict[str, str] = {}
  for part in cookies.split(";"):
    part = part.strip()
    if "=" in part:
      k, _, v = part.partition("=")
      result[k.strip()] = v.strip()
  return result


def parse_post_data(raw: str) -> Dict[str, str]:
  """
  Parse a raw POST body string — supports:
    - application/x-www-form-urlencoded  (key=value&key2=value2)
    - JSON                               ({"key": "value"})
  Returns a flat dict.
  """
  raw = raw.strip()
  if raw.startswith("{"):
    try:
      data = json.loads(raw)
      if isinstance(data, dict):
        return {str(k): str(v) for k, v in data.items()}
    except Exception:
      pass
  # urlencode
  parsed = up.parse_qs(raw, keep_blank_values=True)
  return {k: v[0] if v else "" for k, v in parsed.items()}
