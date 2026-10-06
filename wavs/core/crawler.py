from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import (
    parse_qsl,
    urldefrag,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

from bs4 import BeautifulSoup

from wavs.core.http_client import HttpClient

DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_PAGES = 100
_SKIP_INPUT_TYPES = {"submit", "button", "reset", "image", "file"}


@dataclass
class InjectionPoint:
    method: str
    url: str
    param: str
    params: dict[str, str]


@dataclass
class CrawlResult:
    urls: list[str]
    injection_points: list[InjectionPoint]


class Crawler:
    def __init__(
        self,
        client: HttpClient,
        *,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_pages: int = DEFAULT_MAX_PAGES,
        scope: str | None = None,
    ) -> None:
        self.client = client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.scope = scope

    async def crawl(self, seed: str) -> CrawlResult:
        scope = self.scope or urlparse(seed).netloc
        visited: set[str] = set()
        urls: list[str] = []
        points: list[InjectionPoint] = []
        seen_points: set[tuple[str, str, str, tuple[str, ...]]] = set()
        current = [seed]
        depth = 0
        while current and depth <= self.max_depth and len(visited) < self.max_pages:
            batch: list[str] = []
            for url in current:
                key = self._normalize(url)
                if key in visited or len(visited) >= self.max_pages:
                    continue
                visited.add(key)
                batch.append(url)
            responses = await asyncio.gather(*(self.client.get(u) for u in batch))
            next_level: list[str] = []
            for url, resp in zip(batch, responses):
                if resp is None:
                    continue
                if "html" not in resp.headers.get("content-type", "").lower():
                    continue
                final_url = str(resp.url)
                urls.append(final_url)
                soup = BeautifulSoup(resp.text, "html.parser")
                self._collect_points(final_url, soup, points, seen_points)
                if depth < self.max_depth:
                    next_level.extend(self._extract_links(soup, final_url, scope))
            current = next_level
            depth += 1
        return CrawlResult(urls, points)

    def _collect_points(
        self,
        page_url: str,
        soup: BeautifulSoup,
        points: list[InjectionPoint],
        seen: set[tuple[str, str, str, tuple[str, ...]]],
    ) -> None:
        for point in self._points_from_query(page_url) + self._points_from_forms(
            page_url, soup
        ):
            key = (point.method, point.url, point.param, tuple(sorted(point.params)))
            if key not in seen:
                seen.add(key)
                points.append(point)

    def _points_from_query(self, url: str) -> list[InjectionPoint]:
        parsed = urlparse(urldefrag(url)[0])
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not query:
            return []
        base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
        return [InjectionPoint("GET", base, name, dict(query)) for name in query]

    def _points_from_forms(
        self, page_url: str, soup: BeautifulSoup
    ) -> list[InjectionPoint]:
        points: list[InjectionPoint] = []
        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            action = urljoin(page_url, form.get("action") or page_url)
            parsed = urlparse(urldefrag(action)[0])
            fields = dict(parse_qsl(parsed.query, keep_blank_values=True))
            fuzzable: list[str] = []
            for name, value, skip in self._form_fields(form):
                fields[name] = value
                if not skip:
                    fuzzable.append(name)
            base = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
            for name in fuzzable:
                points.append(InjectionPoint(method, base, name, dict(fields)))
        return points

    @staticmethod
    def _form_fields(form: object) -> list[tuple[str, str, bool]]:
        fields: list[tuple[str, str, bool]] = []
        for tag in form.find_all(["input", "textarea", "select"]):
            name = tag.get("name")
            if not name:
                continue
            if tag.name == "input":
                itype = (tag.get("type") or "text").lower()
                fields.append((name, tag.get("value", ""), itype in _SKIP_INPUT_TYPES))
            elif tag.name == "textarea":
                fields.append((name, tag.get_text(), False))
            else:
                option = tag.find("option", selected=True) or tag.find("option")
                value = option.get("value", option.get_text()) if option else ""
                fields.append((name, value, False))
        return fields

    def _extract_links(
        self, soup: BeautifulSoup, page_url: str, scope: str
    ) -> list[str]:
        links: list[str] = []
        for anchor in soup.find_all("a", href=True):
            target = urljoin(page_url, anchor["href"])
            parsed = urlparse(target)
            if parsed.scheme in ("http", "https") and parsed.netloc == scope:
                links.append(urldefrag(target)[0])
        return links

    @staticmethod
    def _normalize(url: str) -> str:
        parsed = urlparse(urldefrag(url)[0])
        query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
        return urlunparse(
            (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", query, "")
        )
