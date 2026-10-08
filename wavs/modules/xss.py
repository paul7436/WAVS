from __future__ import annotations

from secrets import token_hex

from bs4 import BeautifulSoup

from wavs.core.crawler import CrawlResult, InjectionPoint
from wavs.modules.base import BaseModule, Finding

_FINDING_TYPE = "reflected-xss"
_MARKER_PREFIX = "wavs"


class XssModule(BaseModule):
    name = "xss"

    async def run(self, target: CrawlResult) -> list[Finding]:
        findings: list[Finding] = []
        for point in target.injection_points:
            finding = await self._test_point(point)
            if finding is not None:
                findings.append(finding)
        return findings

    async def _test_point(self, point: InjectionPoint) -> Finding | None:
        marker = _MARKER_PREFIX + token_hex(4)
        tag_payload = f"<{marker}>"
        response = await self._send(point, tag_payload)
        if response is None or marker not in response.text:
            return None
        if self._tag_injected(response.text, marker):
            return self._finding(
                point,
                tag_payload,
                "high",
                f"The injected element <{marker}> was reflected unescaped and "
                "parsed as an HTML tag, so script-bearing markup could be "
                "injected.",
            )
        return await self._quote_probe(point, marker)

    async def _quote_probe(self, point: InjectionPoint, marker: str) -> Finding | None:
        payload = f"{marker}\"'"
        response = await self._send(point, payload)
        if response is None:
            return None
        text = response.text
        for quote, label in (('"', "double"), ("'", "single")):
            if marker + quote in text:
                return self._finding(
                    point,
                    payload,
                    "medium",
                    f"A {label} quote was reflected unescaped next to the "
                    f"marker ({marker}{quote}), allowing a possible attribute "
                    "breakout.",
                )
        return None

    async def _send(self, point: InjectionPoint, value: str):
        data = dict(point.params)
        data[point.param] = value
        if point.method == "POST":
            return await self.client.post(point.url, data=data)
        return await self.client.get(point.url, params=data)

    def _finding(
        self, point: InjectionPoint, payload: str, severity: str, detail: str
    ) -> Finding:
        return Finding(
            _FINDING_TYPE,
            point.url,
            severity,
            f"Possible reflected XSS in parameter '{point.param}'. {detail} "
            "Detection only; a benign unique marker was used.",
            param=point.param,
            evidence=f"{point.method} {point.url} {point.param}={payload!r}",
        )

    @staticmethod
    def _tag_injected(text: str, marker: str) -> bool:
        soup = BeautifulSoup(text, "html.parser")
        return soup.find(marker) is not None
