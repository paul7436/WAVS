from __future__ import annotations

import argparse
import asyncio
import sys

from wavs.core.crawler import Crawler
from wavs.core.http_client import HttpClient
from wavs.modules.base import Finding
from wavs.modules.csrf import CsrfModule
from wavs.modules.headers import HeadersModule
from wavs.modules.sensitive_files import SensitiveFilesModule
from wavs.modules.sqli import SqliModule
from wavs.modules.xss import XssModule
from wavs.report.reporter import Reporter, ScanReport

MODULES = {
    "headers": HeadersModule,
    "sensitive_files": SensitiveFilesModule,
    "sqli": SqliModule,
    "xss": XssModule,
    "csrf": CsrfModule,
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="wavs",
        description="WAVS - modular web application vulnerability scanner. "
        "Educational use only, against targets you are authorised to test.",
    )
    parser.add_argument("target", help="Seed URL, e.g. http://localhost:8080/")
    parser.add_argument(
        "-m", "--modules", default="all",
        help=f"Comma-separated modules to run (default: all). Available: {', '.join(MODULES)}",
    )
    parser.add_argument("--cookies", help="Cookie string, e.g. 'PHPSESSID=abc; security=low'")
    parser.add_argument("--delay", type=float, default=0.0, help="Seconds between requests")
    parser.add_argument("--concurrency", type=int, default=10, help="Max concurrent requests")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout (seconds)")
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum crawl depth")
    parser.add_argument("--max-pages", type=int, default=100, help="Maximum pages to crawl")
    parser.add_argument("--user-agent", help="Override the User-Agent header")
    parser.add_argument("--wordlist", help="Wordlist path for the sensitive_files module")
    parser.add_argument("--sqli-sleep", type=int, default=5, help="Delay for time-based SQLi probes")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--json", dest="json_path", help="Write a JSON report to this path")
    parser.add_argument("--html", dest="html_path", help="Write an HTML report to this path")
    return parser.parse_args(argv)


def selected_modules(spec: str) -> list[str]:
    if spec == "all":
        return list(MODULES)
    names = [name.strip() for name in spec.split(",") if name.strip()]
    unknown = [name for name in names if name not in MODULES]
    if unknown:
        raise SystemExit(
            f"Unknown module(s): {', '.join(unknown)}. Available: {', '.join(MODULES)}"
        )
    return names


def parse_cookies(raw: str | None) -> dict[str, str]:
    cookies: dict[str, str] = {}
    if not raw:
        return cookies
    for pair in raw.split(";"):
        if "=" in pair:
            name, value = pair.split("=", 1)
            cookies[name.strip()] = value.strip()
    return cookies


def build_module(name: str, client: HttpClient, args: argparse.Namespace):
    if name == "sensitive_files":
        return SensitiveFilesModule(client, wordlist=args.wordlist)
    if name == "sqli":
        return SqliModule(client, time_sleep=args.sqli_sleep)
    return MODULES[name](client)


async def scan(args: argparse.Namespace) -> ScanReport:
    module_names = selected_modules(args.modules)
    cookies = parse_cookies(args.cookies)
    client_kwargs = {
        "timeout": args.timeout,
        "delay": args.delay,
        "max_concurrency": args.concurrency,
        "cookies": cookies or None,
        "verify": not args.insecure,
    }
    if args.user_agent:
        client_kwargs["user_agent"] = args.user_agent

    findings: list[Finding] = []
    async with HttpClient(**client_kwargs) as client:
        crawler = Crawler(client, max_depth=args.max_depth, max_pages=args.max_pages)
        _log(f"Crawling {args.target} ...")
        target = await crawler.crawl(args.target)
        _log(f"{len(target.urls)} page(s), {len(target.injection_points)} injection point(s)")
        for name in module_names:
            _log(f"Running module: {name} ...")
            results = await build_module(name, client, args).run(target)
            _log(f"  -> {len(results)} finding(s)")
            findings.extend(results)
    return ScanReport(target=args.target, findings=findings)


def print_summary(report: ScanReport) -> None:
    summary = report.summary()
    print(f"\nScan of {report.target} - {summary['total']} finding(s)")
    for severity in ("high", "medium", "low", "info"):
        print(f"  {severity:>6}: {summary[severity]}")
    if report.findings:
        print()
    for finding in report.sorted_findings():
        param = f" [{finding.param}]" if finding.param else ""
        print(f"[{finding.severity.upper()}] {finding.type}{param} - {finding.url}")


def _log(message: str) -> None:
    print(f"[*] {message}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = asyncio.run(scan(args))
    Reporter().save(report, json_path=args.json_path, html_path=args.html_path)
    print_summary(report)
    if args.json_path:
        print(f"\nJSON report written to {args.json_path}")
    if args.html_path:
        print(f"HTML report written to {args.html_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
