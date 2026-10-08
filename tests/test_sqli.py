import asyncio
import re
import time

from tests._util import serve
from wavs.core.crawler import CrawlResult, InjectionPoint
from wavs.core.http_client import HttpClient
from wavs.modules.sqli import SqliModule

_LONG = "<html><body>" + "record " * 200 + "</body></html>"
_SHORT = "<html><body>no results</body></html>"
_ERROR = "<html><body>You have an error in your SQL syntax; MySQL</body></html>"


def _responder(path, query):
    value = query.get("id", [""])[0]
    if path == "/time":
        match = re.search(r"(?:SLEEP|pg_sleep)\((\d+)\)|DELAY '0:0:(\d+)'", value, re.I)
        if match:
            time.sleep(int(match.group(1) or match.group(2)))
        return (_LONG, 200, None)
    if path == "/err":
        return (_ERROR if ("'" in value or '"' in value) else _LONG, 200, None)
    if path == "/bool":
        return (_SHORT if ("1=2" in value or "'1'='2" in value) else _LONG, 200, None)
    return (_LONG, 200, None)


def _point(base, path):
    return InjectionPoint("GET", f"{base}{path}", "id", {"id": "1"})


def test_sqli_detects_each_technique_without_false_positive():
    async def run():
        with serve(_responder) as base:
            points = [_point(base, p) for p in ("/err", "/bool", "/time", "/safe")]
            async with HttpClient(timeout=10) as client:
                findings = await SqliModule(client, time_sleep=1).run(
                    CrawlResult(urls=[], injection_points=points)
                )
            return findings

    findings = asyncio.run(run())
    technique = {
        f.url.rsplit("/", 1)[1]: re.search(r"\((.*?)\)", f.description).group(1)
        for f in findings
    }
    assert technique.get("err") == "error-based"
    assert technique.get("bool") == "boolean-based"
    assert technique.get("time") == "time-based"
    assert "safe" not in technique
    assert all(f.severity == "high" and f.type == "sql-injection" for f in findings)
