import asyncio

from tests._util import crawl_result, serve
from wavs.core.http_client import HttpClient
from wavs.modules.headers import HeadersModule

_SECURE = {
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
    "X-Content-Type-Options": "nosniff",
}


def _missing(path, query):
    return ("<html></html>", 200, None)


def _secure(path, query):
    return ("<html></html>", 200, dict(_SECURE))


def _run(responder):
    async def run():
        with serve(responder) as base:
            async with HttpClient() as client:
                return await HeadersModule(client).run(crawl_result([base + "/"]))

    return asyncio.run(run())


def test_missing_headers_are_reported():
    findings = _run(_missing)
    types = {f.description.split(";")[0] for f in findings}
    assert any("Content-Security-Policy" in t for t in types)
    assert all(f.type == "missing-security-header" for f in findings)
    assert len(findings) >= 5


def test_secure_headers_produce_no_findings():
    assert _run(_secure) == []
