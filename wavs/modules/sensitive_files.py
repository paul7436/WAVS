from __future__ import annotations

import asyncio
from pathlib import Path
from secrets import token_hex
from urllib.parse import urljoin, urlparse, urlunparse

from wavs.core.crawler import CrawlResult
from wavs.modules.base import BaseModule, Finding

DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent / "wordlists" / "common.txt"
_FINDING_TYPE = "sensitive-file"
_INTERESTING = {200, 401, 403}
_LENGTH_TOLERANCE = 0.1
_HIGH_MARKERS = (
    ".env",
    ".git",
    ".svn",
    ".hg",
    "id_rsa",
    ".ssh",
    ".htpasswd",
    ".aws",
    "wp-config",
    "config.php",
    "configuration.php",
    "settings.py",
    "credentials",
    "secrets",
    "backup",
    "dump",
    ".sql",
    ".bak",
)


class SensitiveFilesModule(BaseModule):
    name = "sensitive_files"

    def __init__(self, client, *, wordlist: str | Path | None = None) -> None:
        super().__init__(client)
        self.wordlist = self._load(Path(wordlist) if wordlist else DEFAULT_WORDLIST)

    async def run(self, target: CrawlResult) -> list[Finding]:
        findings: list[Finding] = []
        for origin in self._origins(target.urls):
            findings.extend(await self._scan(origin))
        return findings

    async def _scan(self, origin: str) -> list[Finding]:
        baseline = await self._baseline(origin)
        probes = await asyncio.gather(
            *(self._probe(origin, path, baseline) for path in self.wordlist)
        )
        return [finding for finding in probes if finding is not None]

    async def _baseline(self, origin: str) -> tuple[int | None, int]:
        response = await self.client.get(urljoin(origin + "/", token_hex(16)))
        if response is None:
            return (None, 0)
        return (response.status_code, len(response.content))

    async def _probe(
        self, origin: str, path: str, baseline: tuple[int | None, int]
    ) -> Finding | None:
        url = urljoin(origin + "/", path.lstrip("/"))
        response = await self.client.get(url)
        if response is None:
            return None
        status = response.status_code
        if status not in _INTERESTING:
            return None
        base_status, base_length = baseline
        length = len(response.content)
        if status == 200 and base_status == 200 and self._similar(length, base_length):
            return None
        return Finding(
            _FINDING_TYPE,
            url,
            self._severity(path, status),
            self._describe(path, status),
            evidence=f"HTTP {status} at {url} ({length} bytes)",
        )

    @staticmethod
    def _describe(path: str, status: int) -> str:
        if status == 200:
            return (
                f"Path '{path}' is reachable and returned HTTP 200; it may "
                "expose sensitive content."
            )
        return (
            f"Path '{path}' exists but access is restricted (HTTP {status}); "
            "its presence is still disclosed."
        )

    @staticmethod
    def _severity(path: str, status: int) -> str:
        lowered = path.lower()
        if any(marker in lowered for marker in _HIGH_MARKERS):
            return "high"
        if status in (401, 403):
            return "low"
        return "medium"

    @staticmethod
    def _similar(length: int, baseline: int) -> bool:
        if baseline == 0:
            return length == 0
        return abs(length - baseline) / baseline < _LENGTH_TOLERANCE

    @staticmethod
    def _origins(urls: list[str]) -> list[str]:
        origins: list[str] = []
        for url in urls:
            parsed = urlparse(url)
            if not parsed.netloc:
                continue
            origin = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
            if origin not in origins:
                origins.append(origin)
        return origins

    @staticmethod
    def _load(path: Path) -> list[str]:
        entries: list[str] = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                entries.append(stripped)
        return entries
