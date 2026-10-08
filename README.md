# WAVS - Web Application Vulnerability Scanner

A modular, asynchronous web application vulnerability scanner written in Python.
WAVS crawls a target in scope, collects injection points (links and forms), and
runs a set of independent detection modules that report normalised findings.

> **Status: all planned modules implemented.** The scanner crawls a target,
> runs every detection module, and writes JSON and HTML reports. See the
> roadmap below.

## ⚠️ Legal & ethical scope

This is an **educational** auditing tool. Only ever run it against systems you
own or are **explicitly authorised** to test. During development it is used
**exclusively** against local, intentionally vulnerable targets such as
[DVWA](https://github.com/digininja/DVWA) and
[OWASP Juice Shop](https://github.com/juice-shop/juice-shop) running in Docker.

Scanning systems without permission is illegal. You are solely responsible for
how you use this software.

## Architecture

```
HTTP engine  ->  Crawler  ->  Detection modules  ->  Reporting
```

Every detection module shares the same interface: it receives an injection
point and returns normalised `Finding` objects. Adding a module never affects
the others.

```
wavs/
├── core/
│   ├── http_client.py      # async HTTP wrapper (cookies, timeout, UA, delay, retries)
│   └── crawler.py          # link/form discovery, scope, dedup, injection points
├── modules/
│   ├── base.py             # common module interface
│   ├── headers.py          # missing security headers
│   ├── sensitive_files.py  # wordlist-based discovery
│   ├── sqli.py             # SQL injection (detection only)
│   ├── xss.py              # reflected XSS (unique marker)
│   └── csrf.py             # forms without an anti-CSRF token
├── report/
│   └── reporter.py         # JSON + HTML report
├── wordlists/
│   ├── common.txt          # bundled SecLists common.txt (MIT)
│   └── SOURCES.md          # wordlist origins and licences
└── main.py                 # CLI

tests/                      # pytest suite (one file per component)
```

## Roadmap

- [x] HTTP engine
- [x] Crawler
- [x] Security headers module
- [x] Sensitive files module
- [x] SQL injection module (detection)
- [x] Reflected XSS module
- [x] CSRF module
- [x] Reporting (JSON + HTML)
- [x] CLI, documentation, tests

## Requirements

- Python 3.11+
- See `requirements.txt`

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

Run the scanner as a module from the project root:

```bash
python -m wavs.main http://localhost:8080/
```

Scan an authenticated session and write both reports:

```bash
python -m wavs.main http://localhost:8080/ \
    --cookies "PHPSESSID=abc123; security=low" \
    --delay 0.2 \
    --json report.json \
    --html report.html
```

Run only selected modules:

```bash
python -m wavs.main http://localhost:8080/ --modules headers,csrf
```

### Options

| Option | Description | Default |
| --- | --- | --- |
| `target` | Seed URL to crawl and scan | *(required)* |
| `-m`, `--modules` | Comma-separated modules, or `all` | `all` |
| `--cookies` | Cookie string, e.g. `name=value; name2=value2` | – |
| `--delay` | Seconds between requests (be gentle) | `0.0` |
| `--concurrency` | Maximum concurrent requests | `10` |
| `--timeout` | Per-request timeout in seconds | `10.0` |
| `--max-depth` | Maximum crawl depth | `2` |
| `--max-pages` | Maximum pages to crawl | `100` |
| `--user-agent` | Override the User-Agent header | *(WAVS UA)* |
| `--wordlist` | Wordlist for the `sensitive_files` module | bundled list |
| `--sqli-sleep` | Delay for time-based SQLi probes | `5` |
| `--insecure` | Disable TLS certificate verification | off |
| `--json` / `--html` | Write a report to the given path | – |

Available modules: `headers`, `sensitive_files`, `sqli`, `xss`, `csrf`.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

The suite spins up local mock servers and checks each module end to end,
including the full CLI pipeline. No external target is contacted.

## Credits

- Bundled wordlist `wavs/wordlists/common.txt` comes from
  [SecLists](https://github.com/danielmiessler/SecLists) (MIT). See
  `wavs/wordlists/SOURCES.md`.
