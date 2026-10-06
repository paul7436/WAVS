from __future__ import annotations

from typing import Mapping
from urllib.parse import urlparse

from wavs.core.crawler import CrawlResult
from wavs.modules.base import BaseModule, Finding

_FINDING_TYPE = "missing-security-header"

_ABSENCE_CHECKS = (
    (
        "Content-Security-Policy",
        "medium",
        "No Content-Security-Policy header; nothing restricts the sources a "
        "page may load, weakening defence against XSS and data injection.",
    ),
    (
        "X-Frame-Options",
        "medium",
        "No X-Frame-Options header; the page may be framed by other sites, "
        "enabling clickjacking.",
    ),
    (
        "Referrer-Policy",
        "low",
        "No Referrer-Policy header; full referrer URLs may leak to third "
        "parties.",
    ),
    (
        "Permissions-Policy",
        "info",
        "No Permissions-Policy header; powerful browser features are not "
        "restricted.",
    ),
)


class HeadersModule(BaseModule):
    name = "headers"

    async def run(self, target: CrawlResult) -> list[Finding]:
        findings: list[Finding] = []
        for url in target.urls:
            response = await self.client.get(url)
            if response is None:
                continue
            findings.extend(self._check(url, response.headers))
        return findings

    def _check(self, url: str, headers: Mapping[str, str]) -> list[Finding]:
        present = {key.lower(): value for key, value in headers.items()}
        findings: list[Finding] = []
        for name, severity, description in _ABSENCE_CHECKS:
            if name.lower() not in present:
                findings.append(
                    Finding(_FINDING_TYPE, url, severity, description,
                            evidence=f"{name} header is absent")
                )
        nosniff = present.get("x-content-type-options", "").strip().lower()
        if nosniff != "nosniff":
            seen = present.get("x-content-type-options", "(absent)")
            findings.append(
                Finding(_FINDING_TYPE, url, "low",
                        "X-Content-Type-Options is not set to nosniff; the "
                        "browser may MIME-sniff responses.",
                        evidence=f"X-Content-Type-Options: {seen}")
            )
        if urlparse(url).scheme == "https" and "strict-transport-security" not in present:
            findings.append(
                Finding(_FINDING_TYPE, url, "medium",
                        "No Strict-Transport-Security header on an HTTPS "
                        "response; HTTPS is not enforced for future visits.",
                        evidence="Strict-Transport-Security header is absent")
            )
        return findings
