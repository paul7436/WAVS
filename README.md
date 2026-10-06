# WAVS - Web Application Vulnerability Scanner

A modular, asynchronous web application vulnerability scanner written in Python.
WAVS crawls a target in scope, collects injection points (links and forms), and
runs a set of independent detection modules that report normalised findings.

> **Status: work in progress.** Modules are built one at a time. See the
> roadmap below for what is implemented.

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
├── main.py                 # CLI
└── README.md
```

## Roadmap

- [x] HTTP engine
- [ ] Crawler
- [ ] Security headers module
- [ ] Sensitive files module
- [ ] SQL injection module (detection)
- [ ] Reflected XSS module
- [ ] CSRF module
- [ ] Reporting (JSON + HTML)
- [ ] CLI, documentation, tests

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

The command-line interface is not wired up yet. This section will be completed
once the CLI module lands.
