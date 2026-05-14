# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""BreachSQL — SQL injection payloads"""

from commonhuman_payloads.sqli import (
    ERROR_PAYLOADS,
    DB_ERROR_PATTERNS,
    get_error_payloads,
    BOOLEAN_PAIRS,
    BOOLEAN_PAIRS_RISK2,
    get_boolean_pairs,
    TIME_PAYLOADS,
    get_time_payloads,
    CONCAT_PAYLOADS,
    SUBSTRING_PROBES,
    make_marker,
    get_concat_payloads,
    get_substring_probes,
    make_substring_payload,
    order_by_probes,
    union_null_probes,
    OOB_PAYLOADS,
    get_oob_payloads,
    DB_CONTENTS_PAYLOADS,
    get_db_contents_payloads,
    STACKED_PAYLOADS,
    get_stacked_payloads,
    DIOS_PAYLOADS,
    get_dios_payloads,
    LFI_PAYLOADS,
    get_lfi_payloads,
    PRIVESC_PAYLOADS,
    get_privesc_payloads,
    ENUM_PAYLOADS,
    get_enum_payloads,
)
from commonhuman_payloads.sqli.union import BREACH_MARKER_PREFIX
from commonhuman_payloads.encoders import apply_evasion

__all__ = [
    # error
    "ERROR_PAYLOADS",
    "DB_ERROR_PATTERNS",
    "get_error_payloads",
    # boolean
    "BOOLEAN_PAIRS",
    "BOOLEAN_PAIRS_RISK2",
    "get_boolean_pairs",
    # time
    "TIME_PAYLOADS",
    "get_time_payloads",
    # union / markers
    "BREACH_MARKER_PREFIX",
    "make_marker",
    "CONCAT_PAYLOADS",
    "SUBSTRING_PROBES",
    "get_concat_payloads",
    "get_substring_probes",
    "make_substring_payload",
    "order_by_probes",
    "union_null_probes",
    # oob
    "OOB_PAYLOADS",
    "get_oob_payloads",
    # advanced
    "DB_CONTENTS_PAYLOADS",
    "get_db_contents_payloads",
    "STACKED_PAYLOADS",
    "get_stacked_payloads",
    "DIOS_PAYLOADS",
    "get_dios_payloads",
    "LFI_PAYLOADS",
    "get_lfi_payloads",
    "PRIVESC_PAYLOADS",
    "get_privesc_payloads",
    "ENUM_PAYLOADS",
    "get_enum_payloads",
    # evasion
    "apply_evasion",
]
