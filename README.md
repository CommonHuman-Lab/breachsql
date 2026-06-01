# BreachSQL
<p align="center">
  <img src="assets/BreachSQL_logo.png" alt="BreachSQL" width="300"/>
</p>
<!-- markdownlint-disable MD033 -->
<p align="center">
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-AGPL--3.0-white?style=for-the-badge&logo=opensourceinitiative&logoColor=black" alt="License">
  </a>
  <img src="https://img.shields.io/badge/Python-3.10+-black?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <a href="https://github.com/CommonHuman-Lab/gloomproxy">
    <img src="https://img.shields.io/badge/GloomProxy-Plugin-black?style=for-the-badge" alt="GloomProxy Plugin">
  </a>
</p>
<!-- markdownlint-enable MD033 -->

**Fast SQL injection scanner with built-in exploitation** — detect and extract in one command, across all major backends, with WAF evasion baked in. No Java. No license. Drops into a Python pipeline.

<!-- markdownlint-disable MD033 -->
<p align="center">
  <img src="assets/breachsql_demo.gif" alt="BreachSQL demo" width="800"/>
</p>
<!-- markdownlint-enable MD033 -->

```bash
# Kali / Debian / Ubuntu — use a virtual env (required on externally-managed Python)
python3 -m venv .venv && source .venv/bin/activate
pip install breachsql

# Scan, exploit, and dump everything — outputs written to 127.0.0.1/
breachsql -u "http://127.0.0.1:17476/challenges/my1/secrets?id=1" --exploit

```

> Point it at a target. Get findings. Drop it in a pipeline.

---

## Why BreachSQL?

- **Faster** — binary-search boolean extraction, parallel surface probing, no per-request sleep loops
- **Detect → exploit in one pass** — `--exploit` dumps every discovered table and writes `.txt`, `.json`, and `.html` outputs to a `<host>/` folder automatically; `--dump TABLE` targets a single table
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

# Exploit: dump every table, write target.com/{txt,json,html} automatically
breachsql -u "https://target.com/users?id=1" --exploit

# Exploits, and save results to a custom output stem
breachsql -u "https://target.com/users?id=1" --exploit -o results/target

# Stream JSON to stdout (pipeline-friendly)
breachsql -u "https://target.com/users?id=1" --json | jq .

# Save plain-text summary separately
breachsql -u "https://target.com/users?id=1" --text summary.txt

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

Combine with `--technique EBTUS` to run all techniques in a single pass.

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
| `--technique` | `EBTUS` | Techniques to run (any combo of E B T U S) |
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
| `--exploit` | — | Exploits and dump every discovered table; auto-creates `<host>/` and writes `<host>.txt`, `<host>.json`, `<host>.html` |
| `--json` | — | Emit findings as JSON to stdout (suppresses banner) |
| `-o STEM` | — | Output stem — writes `<stem>.txt`, `<stem>.json`, `<stem>_dump.json` |
| `--text FILE` | — | Write plain-text summary to FILE |
| `--report-html` | — | Write a self-contained HTML report to this file |

---

## GloomProxy Plugin

BreachSQL ships pre-installed with [GloomProxy](https://github.com/CommonHuman-Lab/gloomproxy) and appears in the workspace UI out of the box — no extra setup needed.

---

## Fire Range

The **BreachSQL Fire Range** is a deliberately vulnerable Flask + MySQL + PostgreSQL + SQLite app that ships with [OctoRig](https://github.com/CommonHuman-Lab/OctoRig).

```bash
# Start the Fire Range (OctoRig required)
./octorig.sh start breachsql

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

## Legal & Ethical Use

Only run BreachSQL against applications you own or have explicit written authorization to test. Authorized use includes penetration testing engagements, bug bounty programs within defined scope, and CTF competitions.

`--exploit`, `--dump`, and `--dump-all` extract live database content — only use them where data extraction is explicitly permitted by your engagement scope.

The authors accept no liability for unauthorized or illegal use.

---

## License

Licensed under the [AGPLv3](LICENSE). You are free to use, modify, and distribute this software. If you run it as a service or distribute it, the source must remain open.

For commercial licensing, contact the author.
