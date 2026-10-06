from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

from wavs.core.crawler import CrawlResult
from wavs.core.http_client import HttpClient

SEVERITIES = ("info", "low", "medium", "high")


@dataclass
class Finding:
    type: str
    url: str
    severity: str
    description: str
    param: str | None = None
    evidence: str = ""


class BaseModule(ABC):
    name: ClassVar[str] = "base"

    def __init__(self, client: HttpClient) -> None:
        self.client = client

    @abstractmethod
    async def run(self, target: CrawlResult) -> list[Finding]:
        ...
