# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""GloomProxy plugin wrapper for BreachSQL.

This is a thin adapter. All offensive logic lives in breachsql.engine.
"""
from __future__ import annotations

import asyncio
import logging

from gloomproxy_sdk import BaseScanner, Finding, ScanContext, Target, ScanOptionDef
from gloomproxy_sdk.capabilities import PluginCapabilities
from gloomproxy_sdk.manifest import PluginManifest, TrustLevel

from .adapter import build_options
from .mapper import map_results
from .metadata import CAPABILITIES

log = logging.getLogger(__name__)


class BreachSQLPlugin(BaseScanner):
    name = "breachsql"
    version = "0.1.7"
    description = "Context-aware SQL injection scanner with WAF detection and evasion"
    author = "CommonHuman-Lab"
    tags = ["sqli", "active", "http"]

    @classmethod
    def capabilities(cls) -> PluginCapabilities:
        return CAPABILITIES

    @classmethod
    def manifest(cls) -> PluginManifest:
        return {
            "trust_level": TrustLevel.CORE,
            "resources": {"max_runtime": 600, "max_findings": 5000},
            "sdk_min_version": "0.1.0",
        }

    @classmethod
    def option_schema(cls) -> list[ScanOptionDef]:
        return [
            {"key": "crawl",     "label": "Crawl",      "type": "bool",   "default": False, "description": "Crawl site to discover injectable pages"},
            {"key": "level",     "label": "Level",      "type": "select", "default": "1",   "description": "Injection depth and aggressiveness",
             "choices": [{"value": "1", "label": "1 — Fast"}, {"value": "2", "label": "2 — Normal"}, {"value": "3", "label": "3 — Deep"}]},
            {"key": "risk",      "label": "Risk",       "type": "select", "default": "1",   "description": "Payload risk level",
             "choices": [{"value": "1", "label": "1 — Safe"}, {"value": "2", "label": "2 — Medium"}, {"value": "3", "label": "3 — Aggressive"}]},
            {"key": "technique", "label": "Techniques", "type": "select", "default": "EBTUO", "description": "SQLi techniques to test",
             "choices": [
                 {"value": "EBTUO", "label": "All techniques"},
                 {"value": "E",     "label": "Error-based"},
                 {"value": "B",     "label": "Boolean blind"},
                 {"value": "T",     "label": "Time-based"},
                 {"value": "U",     "label": "UNION-based"},
             ]},
            {"key": "dbms",    "label": "DBMS",    "type": "select", "default": "auto", "description": "Target database type",
             "choices": [
                 {"value": "auto",     "label": "Auto-detect"},
                 {"value": "mysql",    "label": "MySQL / MariaDB"},
                 {"value": "postgres", "label": "PostgreSQL"},
                 {"value": "mssql",    "label": "MSSQL"},
                 {"value": "oracle",   "label": "Oracle"},
                 {"value": "sqlite",   "label": "SQLite"},
             ]},
            {"key": "threads", "label": "Threads", "type": "int", "default": 5, "description": "Concurrent request threads", "min": 1, "max": 20},
        ]

    def initialize(self, context: ScanContext) -> None:
        self._options = build_options(context)

    async def scan(self, target: Target) -> list[Finding]:
        from breachsql.engine.scanner import scan as breachsql_scan

        options = self._options
        url = target.url

        await self.ctx.events.progress("Starting BreachSQL scan", 0.0)

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None, breachsql_scan, url, options
            )
        except Exception as exc:
            log.exception("BreachSQL engine error for %s", url)
            await self.ctx.events.debug(f"BreachSQL engine error: {exc}")
            return []

        findings = map_results(result)

        await self.ctx.events.progress(
            f"BreachSQL complete — {len(findings)} finding(s)", 1.0
        )
        log.info("BreachSQL: %d finding(s) for %s", len(findings), url)
        return findings
