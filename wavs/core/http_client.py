from __future__ import annotations

import asyncio
import time
from types import TracebackType
from typing import Any

import httpx

DEFAULT_USER_AGENT = "WAVS/0.1 (+https://github.com/paul7436/WAVS)"
DEFAULT_TIMEOUT = 10.0
DEFAULT_RETRIES = 2
DEFAULT_DELAY = 0.0
DEFAULT_MAX_CONCURRENCY = 10
_FALLBACK_BACKOFF = 0.5


class HttpClient:
    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        user_agent: str = DEFAULT_USER_AGENT,
        cookies: dict[str, str] | None = None,
        delay: float = DEFAULT_DELAY,
        retries: int = DEFAULT_RETRIES,
        max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
        verify: bool = True,
        follow_redirects: bool = True,
    ) -> None:
        self.delay = delay
        self.retries = retries
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._throttle_lock = asyncio.Lock()
        self._last_request = 0.0
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": user_agent},
            cookies=cookies,
            verify=verify,
            follow_redirects=follow_redirects,
        )

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _throttle(self) -> None:
        if self.delay <= 0:
            return
        async with self._throttle_lock:
            wait = self._last_request + self.delay - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_request = time.monotonic()

    async def request(
        self, method: str, url: str, **kwargs: Any
    ) -> httpx.Response | None:
        for attempt in range(self.retries + 1):
            await self._throttle()
            async with self._semaphore:
                try:
                    return await self._client.request(method, url, **kwargs)
                except httpx.HTTPError:
                    if attempt >= self.retries:
                        return None
            await asyncio.sleep(self.delay or _FALLBACK_BACKOFF)
        return None

    async def get(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response | None:
        return await self.request("POST", url, **kwargs)
