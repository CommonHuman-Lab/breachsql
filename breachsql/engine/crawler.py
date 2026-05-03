# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — engine/crawler.py
Multi-threaded BFS web crawler.

Discovers links and HTML forms within a target origin.
Respects same-origin constraint, max depth, and max page limits.

Returns:
  - A list of (url, method, params) tuples representing discovered
    injectable surfaces.
  - A list of all crawled URLs (for DOM scanning).
"""

from __future__ import annotations

import urllib.parse as up
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple

from .http.injector import Injector

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class FormTarget:
  method:    str                   # GET | POST
  params:    Dict[str, str]        # {name: default_value} — injectable params
  action:    str                   # resolved form action URL
  base_data: Dict[str, str] = field(default_factory=dict)  # hidden + non-injectable fields


@dataclass
class CrawlResult:
  visited_urls:  List[str]          = field(default_factory=list)
  form_targets:  List[FormTarget]   = field(default_factory=list)
  url_params:    List[Tuple[str, List[str]]] = field(default_factory=list)  # (url, [param_names])
  page_sources:  Dict[str, str]     = field(default_factory=dict)   # url -> html body


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def crawl(
  start_url:       str,
  injector:        Injector,
  max_pages:       int = 50,
  max_depth:       int = 3,
  threads:         int = 5,
  same_origin:     bool = True,
  exclude_patterns: List[str] | None = None,
) -> CrawlResult:
  """
  BFS crawl starting from `start_url`.
  Returns a CrawlResult with all discovered pages, forms, and URL params.

  *exclude_patterns* is a list of regex strings; any URL matching one of
  them is silently skipped.
  """
  import re as _re
  _compiled_excludes = [_re.compile(p) for p in (exclude_patterns or [])]

  def _is_excluded(url: str) -> bool:
      return any(p.search(url) for p in _compiled_excludes)

  result   = CrawlResult()
  visited:  Set[str] = set()
  queue:    deque    = deque()   # (url, depth)
  queue.append((_normalise(start_url), 0))

  with ThreadPoolExecutor(max_workers=threads) as pool:
    while queue and len(visited) < max_pages:
      # Drain current BFS level into a batch
      batch = []
      while queue and len(batch) < threads * 2:
        url, depth = queue.popleft()
        norm = _normalise(url)
        if norm in visited:
          continue
        if same_origin and not injector.same_origin(norm, start_url):
          continue
        if _is_excluded(norm):
          continue
        visited.add(norm)
        batch.append((norm, depth))

      if not batch:
        break

      futures = {pool.submit(_fetch_page, url, injector): (url, depth)
                 for url, depth in batch}

      for future in as_completed(futures):
        url, depth = futures[future]
        try:
          html, links, forms = future.result()
        except Exception:
          continue

        result.visited_urls.append(url)
        result.page_sources[url] = html

        # Collect URL params
        params = injector.get_params(url)
        if params:
          result.url_params.append((url, params))

        # Collect form targets
        for form in forms:
          result.form_targets.append(form)

        # Enqueue new links
        if depth < max_depth:
          for link in links:
            norm = _normalise(link)
            if norm not in visited and not _is_excluded(norm):
              queue.append((norm, depth + 1))

  return result


# ---------------------------------------------------------------------------
# Page fetching and parsing
# ---------------------------------------------------------------------------

def _fetch_page(
  url: str,
  injector: Injector,
) -> Tuple[str, List[str], List[FormTarget]]:
  """
  GET `url`, extract links and forms.
  Returns (html_body, [absolute_links], [FormTarget])
  """
  try:
    resp = injector.get(url)
  except Exception:
    return "", [], []

  if resp.status_code >= 400:
    return "", [], []

  ct = resp.headers.get("content-type", "")
  if "html" not in ct and "javascript" not in ct:
    return "", [], []

  html  = resp.text
  # Use the final URL after any redirects as the base for resolving relative
  # links and form actions.  This is critical for servers that redirect
  # /path → /path/ (301): without it, forms with no action attribute resolve
  # to the pre-redirect URL and POST submissions are silently downgraded to GET.
  effective_url = resp.url if resp.url else url
  links = _extract_links(html, effective_url)
  forms = _extract_forms(html, effective_url)

  return html, links, forms


# ---------------------------------------------------------------------------
# html.parser-based link and form extractors
# ---------------------------------------------------------------------------

class _LinkParser(HTMLParser):
  """Extracts all href values from <a> tags."""

  def __init__(self, base_url: str) -> None:
    super().__init__()
    self.base_url = base_url
    self.links: List[str] = []

  def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
    if tag.lower() != "a":
      return
    attr_dict = {k.lower(): v for k, v in attrs if v is not None}
    href = attr_dict.get("href", "").strip()
    if not href:
      return
    if href.startswith(("javascript:", "mailto:", "#")):
      return
    try:
      abs_url = up.urljoin(self.base_url, href)
      parsed  = up.urlparse(abs_url)
      abs_url = up.urlunparse(parsed._replace(fragment=""))
      self.links.append(abs_url)
    except Exception:
      pass


class _FormParser(HTMLParser):
  """Extracts all HTML forms with their action, method, and input fields."""

  _SKIP_TYPES = {"button", "image", "reset"}
  _SUBMIT_TYPES = {"submit"}
  _HIDDEN_TYPES = {"hidden"}

  def __init__(self, base_url: str) -> None:
    super().__init__()
    self.base_url = base_url
    self.forms: List[FormTarget] = []
    self._in_form = False
    self._current_action = base_url
    self._current_method = "GET"
    self._current_params: Dict[str, str] = {}
    self._current_base: Dict[str, str] = {}

  def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
    tag = tag.lower()
    attr_dict = {k.lower(): (v or "") for k, v in attrs}

    if tag == "form":
      self._in_form = True
      action_raw = attr_dict.get("action", "").strip()
      try:
        self._current_action = (
          up.urljoin(self.base_url, action_raw) if action_raw else self.base_url
        )
      except Exception:
        self._current_action = self.base_url
      self._current_method = attr_dict.get("method", "GET").upper()
      self._current_params = {}
      self._current_base = {}

    elif self._in_form and tag == "input":
      input_type = attr_dict.get("type", "text").lower()
      name = attr_dict.get("name", "").strip()
      if not name:
        return
      if input_type in self._SKIP_TYPES:
        return
      if input_type in self._SUBMIT_TYPES:
        # Submit buttons must be included in base_data so the server processes
        # the form (many PHP apps check for a named submit button).
        if name:
          self._current_base[name] = attr_dict.get("value", "")
        return
      if input_type in self._HIDDEN_TYPES:
        # Hidden inputs go to base_data (sent with every request but not injected)
        self._current_base[name] = attr_dict.get("value", "")
      else:
        self._current_params[name] = attr_dict.get("value", "")

    elif self._in_form and tag in ("textarea", "select"):
      name = attr_dict.get("name", "").strip()
      if name:
        self._current_params[name] = ""

  def handle_endtag(self, tag: str) -> None:
    if tag.lower() == "form" and self._in_form:
      if self._current_params:
        self.forms.append(FormTarget(
          method=self._current_method,
          params=self._current_params,
          action=self._current_action,
          base_data=self._current_base,
        ))
      self._in_form = False
      self._current_params = {}
      self._current_base = {}


def _extract_links(html: str, base_url: str) -> List[str]:
  """Extract and resolve all <a href> URLs using html.parser."""
  parser = _LinkParser(base_url)
  try:
    parser.feed(html)
  except Exception:
    pass
  return parser.links


def _extract_forms(html: str, base_url: str) -> List[FormTarget]:
  """
  Extract all HTML forms using html.parser, returning action URL, method,
  and input field names/default values.
  """
  parser = _FormParser(base_url)
  try:
    parser.feed(html)
  except Exception:
    pass
  return parser.forms


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalise(url: str) -> str:
  """Strip trailing slash and fragment, lowercase scheme+host."""
  try:
    p = up.urlparse(url)
    normalised = up.urlunparse((
      p.scheme.lower(),
      p.netloc.lower(),
      p.path.rstrip("/") or "/",
      p.params,
      p.query,
      "",  # no fragment
    ))
    return normalised
  except Exception:
    return url
