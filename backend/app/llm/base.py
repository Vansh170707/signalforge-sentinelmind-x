"""Provider interfaces. Business logic depends on these protocols, never on vendor SDKs."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx


class ProviderError(Exception):
    """Any provider failure that should trigger failover."""


class RateLimitError(ProviderError):
    """HTTP 429/529: a routing signal, not a fatal error."""

    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class ProviderUnavailable(ProviderError):
    """Provider not configured (no key) or disabled."""


@dataclass
class NarrativeResult:
    provider: str
    model: str
    output: dict[str, Any]
    latency_ms: float
    raw_text: str = ""


@dataclass
class DecisionResult:
    provider: str
    model: str
    decision: dict[str, Any]
    raw: dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0


class NarrativeProvider(Protocol):
    name: str
    model: str

    def available(self) -> bool: ...

    async def generate(self, system: str, user: str, schema: dict[str, Any]) -> NarrativeResult: ...


class DecisionProvider(Protocol):
    name: str
    model: str

    def available(self) -> bool: ...

    async def evaluate(self, state: dict[str, Any]) -> DecisionResult: ...


async def post_json_with_backoff(url: str, *, headers: dict[str, str], body: dict[str, Any], timeout: float,
                                 max_retries: int = 3,
                                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep) -> dict[str, Any]:
    """POST with exponential backoff on 429/529/5xx, bounded by an overall timeout."""

    async def _attempt() -> dict[str, Any]:
        delay = 0.5
        async with httpx.AsyncClient(timeout=timeout) as client:
            for attempt in range(max_retries + 1):
                try:
                    resp = await client.post(url, headers=headers, json=body)
                except httpx.HTTPError as exc:
                    if attempt >= max_retries:
                        raise ProviderError(f"network error: {exc}") from exc
                else:
                    if resp.status_code < 300:
                        return resp.json()
                    retryable = resp.status_code in (429, 529) or resp.status_code >= 500
                    if not retryable or attempt >= max_retries:
                        msg = f"HTTP {resp.status_code}: {resp.text[:300]}"
                        if resp.status_code in (429, 529):
                            raise RateLimitError(msg, _retry_after(resp))
                        raise ProviderError(msg)
                await sleep(delay + random.uniform(0, delay / 2))
                delay *= 2
        raise ProviderError("exhausted retries")

    try:
        return await asyncio.wait_for(_attempt(), timeout=timeout * 2)
    except TimeoutError as exc:
        raise ProviderError("overall timeout") from exc


def _retry_after(resp: httpx.Response) -> float | None:
    value = resp.headers.get("retry-after")
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None
