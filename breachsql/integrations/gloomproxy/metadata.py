# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
from gloomproxy_sdk import PluginCapabilities

CAPABILITIES: PluginCapabilities = {
    "name": "breachsql",
    "modes": ["active"],
    "protocols": ["http", "https"],
    "auth_required": False,
    "distributed_safe": True,
    "vuln_types": [
        "error_based_sqli",
        "boolean_based_sqli",
        "time_based_sqli",
        "union_based_sqli",
        "stacked_sqli",
        "oob_sqli",
    ],
    "proxy_aware": True,
    "min_timeout": 30,
}
