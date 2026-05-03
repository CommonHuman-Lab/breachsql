# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
BreachSQL — engine/_scanner/payloads/
SQL injection payload sets and evasion transforms.

This package is split into focused sub-modules:
  - error      : ERROR_PAYLOADS, DB_ERROR_PATTERNS, get_error_payloads()
  - boolean    : BOOLEAN_PAIRS, get_boolean_pairs()
  - time_based : TIME_PAYLOADS, get_time_payloads()
  - union      : BREACH_MARKER_PREFIX, make_marker(), CONCAT_PAYLOADS,
                 SUBSTRING_PROBES, get_concat_payloads(), get_substring_probes(),
                 make_substring_payload(), order_by_probes(), union_null_probes()
  - oob        : OOB_PAYLOADS, get_oob_payloads()
  - advanced   : DB_CONTENTS_PAYLOADS, STACKED_PAYLOADS, DIOS_PAYLOADS,
                 LFI_PAYLOADS, PRIVESC_PAYLOADS, ENUM_PAYLOADS and their getters
  - evasion    : apply_evasion()

All public names are re-exported here for backward compatibility.
"""

from .error import (
    ERROR_PAYLOADS,
    DB_ERROR_PATTERNS,
    get_error_payloads,
)
from .boolean import (
    BOOLEAN_PAIRS,
    BOOLEAN_PAIRS_RISK2,
    get_boolean_pairs,
)
from .time_based import (
    TIME_PAYLOADS,
    get_time_payloads,
)
from .union import (
    BREACH_MARKER_PREFIX,
    make_marker,
    CONCAT_PAYLOADS,
    SUBSTRING_PROBES,
    get_concat_payloads,
    get_substring_probes,
    make_substring_payload,
    order_by_probes,
    union_null_probes,
)
from .oob import (
    OOB_PAYLOADS,
    get_oob_payloads,
)
from .advanced import (
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
from .evasion import apply_evasion

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
