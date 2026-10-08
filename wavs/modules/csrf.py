from __future__ import annotations

from urllib.parse import urljoin

from bs4 import BeautifulSoup

from wavs.core.crawler import CrawlResult
from wavs.modules.base import BaseModule, Finding

_FINDING_TYPE = "csrf"
_TOKEN_PATTERNS = (
    "csrf",
    "xsrf",
    "_token",
    "authenticity_token",
    "requestverificationtoken",
    "nonce",
)


class CsrfModule(BaseModule):
    name = "csrf"

    async def run(self, target: CrawlResult) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, tuple[str, ...]]] = set()
        for url in target.urls:
            response = await self.client.get(url)
            if response is None:
                continue
            if "html" not in response.headers.get("content-type", "").lower():
                continue
            soup = BeautifulSoup(response.text, "html.parser")
            for form in soup.find_all("form"):
                finding = self._check_form(url, form, seen)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _check_form(self, page_url: str, form, seen) -> Finding | None:
        method = (form.get("method") or "GET").strip().upper()
        if method != "POST":
            return None
        action = urljoin(page_url, form.get("action") or page_url)
        names = self._field_names(form)
        signature = (method, action, tuple(sorted(names)))
        if signature in seen:
            return None
        seen.add(signature)
        if self._has_token(names):
            return None
        return Finding(
            _FINDING_TYPE,
            action,
            "medium",
            "A state-changing POST form exposes no anti-CSRF token field; a "
            "forged cross-site request could submit it on a victim's behalf.",
            evidence=f"form on {page_url} -> {method} {action} fields={sorted(names)}",
        )

    @staticmethod
    def _field_names(form) -> list[str]:
        names: list[str] = []
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if name:
                names.append(name)
        return names

    @staticmethod
    def _has_token(names: list[str]) -> bool:
        for name in names:
            lowered = name.lower()
            if any(pattern in lowered for pattern in _TOKEN_PATTERNS):
                return True
        return False
