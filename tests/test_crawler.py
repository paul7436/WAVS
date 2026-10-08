import asyncio
from urllib.parse import urlparse

from tests._util import serve
from wavs.core.crawler import Crawler
from wavs.core.http_client import HttpClient


def _responder(path, query):
    if path == "/":
        return (
            '<a href="/a?x=1">a</a>'
            '<a href="http://evil.example/">external</a>'
            '<form method="post" action="/login"><input name="user"></form>',
            200,
            None,
        )
    if path == "/a":
        return ("<p>inner page</p>", 200, None)
    return ("missing", 404, None)


def test_crawler_discovers_links_forms_and_respects_scope():
    async def run():
        with serve(_responder) as base:
            async with HttpClient() as client:
                result = await Crawler(client).crawl(base + "/")
            return base, result

    base, result = asyncio.run(run())
    paths = {urlparse(u).path for u in result.urls}
    assert {"/", "/a"} <= paths
    assert not any("evil.example" in u for u in result.urls)

    points = {(p.method, p.param) for p in result.injection_points}
    assert ("GET", "x") in points
    assert ("POST", "user") in points
