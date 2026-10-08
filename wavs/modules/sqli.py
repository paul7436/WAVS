from __future__ import annotations

import re
import time

from wavs.core.crawler import CrawlResult, InjectionPoint
from wavs.modules.base import BaseModule, Finding

_FINDING_TYPE = "sql-injection"
DEFAULT_SLEEP = 5
_TIME_FACTOR = 0.8
_LENGTH_TOLERANCE = 0.02

_ERROR_PAYLOADS = ("'", '"')
_BOOLEAN_PAIRS = (
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    (" AND 1=1", " AND 1=2"),
)
_TIME_TEMPLATES = (
    "' AND SLEEP({n})-- -",
    " AND SLEEP({n})",
    "'; SELECT pg_sleep({n})-- -",
    "'; WAITFOR DELAY '0:0:{n}'-- -",
)

_SQL_ERROR_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"SQL syntax.*MySQL",
        r"Warning.*\bmysqli?_",
        r"valid MySQL result",
        r"MySqlException",
        r"PostgreSQL.*ERROR",
        r"pg_query\(\)",
        r"unterminated quoted string",
        r"quoted string not properly terminated",
        r"ORA-\d{5}",
        r"Oracle.*Driver",
        r"Microsoft OLE DB Provider for SQL Server",
        r"ODBC SQL Server Driver",
        r"Unclosed quotation mark after the character string",
        r"SQLite3?::",
        r"sqlite3\.OperationalError",
        r"System\.Data\.SQLite\.SQLiteException",
    )
)


class SqliModule(BaseModule):
    name = "sqli"

    def __init__(self, client, *, time_sleep: int = DEFAULT_SLEEP) -> None:
        super().__init__(client)
        self.time_sleep = int(time_sleep)

    async def run(self, target: CrawlResult) -> list[Finding]:
        findings: list[Finding] = []
        for point in target.injection_points:
            finding = await self._test_point(point)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _test_point(self, point: InjectionPoint) -> Finding | None:
        baseline = await self._send(point, self._original(point))
        if baseline is None:
            return None
        for technique in (self._error_based, self._boolean_based, self._time_based):
            finding = await technique(point, baseline)
            if finding is not None:
                return finding
        return None

    async def _error_based(self, point: InjectionPoint, baseline) -> Finding | None:
        if _match_error(baseline.text):
            return None
        original = self._original(point)
        for payload in _ERROR_PAYLOADS:
            response = await self._send(point, original + payload)
            if response is None:
                continue
            match = _match_error(response.text)
            if match:
                return self._finding(
                    point,
                    "error-based",
                    original + payload,
                    f"A database error matching /{match}/ appeared after "
                    f"injecting {payload!r} into the parameter.",
                )
        return None

    async def _boolean_based(self, point: InjectionPoint, baseline) -> Finding | None:
        if baseline.status_code != 200:
            return None
        original = self._original(point)
        base_len = len(baseline.content)
        for true_suffix, false_suffix in _BOOLEAN_PAIRS:
            true_resp = await self._send(point, original + true_suffix)
            false_resp = await self._send(point, original + false_suffix)
            if true_resp is None or false_resp is None:
                continue
            if true_resp.status_code != 200 or false_resp.status_code != 200:
                continue
            true_len = len(true_resp.content)
            false_len = len(false_resp.content)
            if _similar(true_len, base_len) and not _similar(false_len, base_len):
                return self._finding(
                    point,
                    "boolean-based",
                    original + true_suffix,
                    f"A TRUE condition matched the baseline ({true_len} vs "
                    f"{base_len} bytes) while a FALSE condition diverged "
                    f"({false_len} bytes).",
                )
        return None

    async def _time_based(self, point: InjectionPoint, baseline) -> Finding | None:
        original = self._original(point)
        control = await self._measure(point, original)
        if control is None:
            return None
        threshold = control + self.time_sleep * _TIME_FACTOR
        for template in _TIME_TEMPLATES:
            payload = original + template.format(n=self.time_sleep)
            elapsed = await self._measure(point, payload)
            if elapsed is None or elapsed < threshold:
                continue
            confirm = await self._measure(point, payload)
            if confirm is not None and confirm >= threshold:
                return self._finding(
                    point,
                    "time-based",
                    payload,
                    f"The response was delayed {elapsed:.1f}s (confirmed "
                    f"{confirm:.1f}s) against a {control:.1f}s baseline after "
                    f"injecting a {self.time_sleep}s sleep.",
                )
        return None

    async def _measure(self, point: InjectionPoint, value: str) -> float | None:
        start = time.monotonic()
        response = await self._send(point, value)
        if response is None:
            return None
        return time.monotonic() - start

    async def _send(self, point: InjectionPoint, value: str):
        data = dict(point.params)
        data[point.param] = value
        if point.method == "POST":
            return await self.client.post(point.url, data=data)
        return await self.client.get(point.url, params=data)

    def _finding(
        self, point: InjectionPoint, technique: str, payload: str, detail: str
    ) -> Finding:
        return Finding(
            _FINDING_TYPE,
            point.url,
            "high",
            f"Possible SQL injection ({technique}) in parameter "
            f"'{point.param}'. {detail} Detection only; no data was extracted.",
            param=point.param,
            evidence=f"{point.method} {point.url} {point.param}={payload!r}",
        )

    @staticmethod
    def _original(point: InjectionPoint) -> str:
        return point.params.get(point.param, "")


def _match_error(text: str) -> str | None:
    for pattern in _SQL_ERROR_PATTERNS:
        if pattern.search(text):
            return pattern.pattern
    return None


def _similar(length: int, baseline: int, tolerance: float = _LENGTH_TOLERANCE) -> bool:
    larger = max(length, baseline, 1)
    return abs(length - baseline) / larger < tolerance
