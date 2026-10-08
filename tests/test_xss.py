import asyncio
import html

from tests._util import serve
from wavs.core.crawler import CrawlResult, InjectionPoint
from wavs.core.http_client import HttpClient
from wavs.modules.xss import XssModule


def _responder(path, query):
    q = query.get("q", [""])[0]
    if path == "/reflect":
        return (f"<html><body>Results for: {q}</body></html>", 200, None)
    if path == "/attr":
        safe = q.replace("<", "").replace(">", "")
        return (f'<html><body><input value="{safe}"></body></html>', 200, None)
    if path == "/escaped":
        return (f"<html><body>{html.escape(q)}</body></html>", 200, None)
    return ("<html><body>static</body></html>", 200, None)


def _point(base, path):
    return InjectionPoint("GET", f"{base}{path}", "q", {"q": "hello"})


def test_xss_flags_tag_injection_and_attribute_breakout():
    async def run():
        with serve(_responder) as base:
            points = [_point(base, p) for p in ("/reflect", "/attr", "/escaped", "/none")]
            async with HttpClient(timeout=10) as client:
                findings = await XssModule(client).run(
                    CrawlResult(urls=[], injection_points=points)
                )
            return findings

    findings = asyncio.run(run())
    by_path = {f.url.rsplit("/", 1)[1]: f for f in findings}
    assert by_path["reflect"].severity == "high"
    assert by_path["attr"].severity == "medium"
    assert "escaped" not in by_path
    assert "none" not in by_path
    assert all(f.type == "reflected-xss" for f in findings)
