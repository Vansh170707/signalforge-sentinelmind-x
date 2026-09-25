"""Narrative providers: Gemini (free tier), Groq (free plan, OpenAI-compatible), Microsoft Foundry (optional).

All use raw HTTPS so no business code imports a vendor SDK. Each returns parsed JSON that the agent
then validates against the brief schema and the incident's evidence.
"""

from __future__ import annotations

import json
import time
from typing import Any

from app.llm.base import (
    NarrativeResult,
    ProviderError,
    ProviderUnavailable,
    RateLimitError,
    post_json_with_backoff,
)


def _parse_json(text: str) -> dict[str, Any]:
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        t = t[t.find("{"):]
    start, end = t.find("{"), t.rfind("}")
    if start < 0 or end < 0:
        raise ProviderError("model returned no JSON object")
    try:
        return json.loads(t[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ProviderError(f"invalid JSON from model: {exc}") from exc


class GeminiProvider:
    """Gemini Developer API generateContent with JSON output constrained by a response schema.

    Free-tier capacity varies: a 503 (model overloaded), 404 (model closed to the key) or timeout on one
    model moves straight to the next configured model instead of retrying the same one."""

    name = "gemini"
    max_pack_chars: int | None = None  # 1M-token context: send the full evidence pack

    def __init__(self, api_key: str, model: str, timeout: float = 35.0, thinking_level: str = "low",
                 fallback_models: list[str] | None = None):
        self.api_key = api_key
        self.model = model
        self.models = [model, *[m for m in (fallback_models or []) if m and m != model]]
        self.timeout = timeout
        self.thinking_level = thinking_level

    def available(self) -> bool:
        return bool(self.api_key)

    async def generate(self, system: str, user: str, schema: dict[str, Any]) -> NarrativeResult:
        if not self.available():
            raise ProviderUnavailable("GEMINI_API_KEY not set")
        errors: list[str] = []
        last: ProviderError | None = None
        for model in self.models:
            t0 = time.perf_counter()
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
            body = {
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}],
                # Gemini 3: keep default temperature (1.0; lower values can loop) and a low thinking level
                # for triage-latency briefs.
                "generationConfig": {"responseMimeType": "application/json", "responseJsonSchema": schema,
                                     "thinkingConfig": {"thinkingLevel": self.thinking_level}},
            }
            try:
                data = await post_json_with_backoff(url, headers={"x-goog-api-key": self.api_key}, body=body,
                                                    timeout=self.timeout, max_retries=0)
            except RateLimitError:
                raise  # quota is per key: another model will not help, let the router fail over
            except ProviderError as exc:
                last = exc
                errors.append(f"{model}: {str(exc)[:120]}")
                continue
            try:
                parts = data["candidates"][0]["content"]["parts"]
                text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
            except (KeyError, IndexError) as exc:
                raise ProviderError(f"unexpected Gemini response: {str(data)[:200]}") from exc
            return NarrativeResult(self.name, data.get("modelVersion", model), _parse_json(text),
                                   round((time.perf_counter() - t0) * 1000, 1), text)
        raise ProviderError("; ".join(errors)) from last


class OpenAICompatibleProvider:
    """Chat Completions with strict JSON-schema output (Groq; Azure/Foundry OpenAI v1 endpoints)."""

    def __init__(self, name: str, base_url: str, api_key: str, model: str, timeout: float = 20.0,
                 auth_header: str = "Authorization", strict_schema: bool = True,
                 extra_body: dict[str, Any] | None = None, max_pack_chars: int | None = None):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.auth_header = auth_header
        self.strict_schema = strict_schema
        self.extra_body = extra_body or {}
        self.max_pack_chars = max_pack_chars  # token budget guard for small free-tier TPM limits

    def available(self) -> bool:
        return bool(self.api_key and self.base_url and self.model)

    async def generate(self, system: str, user: str, schema: dict[str, Any]) -> NarrativeResult:
        if not self.available():
            raise ProviderUnavailable(f"{self.name} not configured")
        t0 = time.perf_counter()
        body: dict[str, Any] = {
            "model": self.model,
            "temperature": 0.2,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            **self.extra_body,
        }
        if self.strict_schema:
            body["response_format"] = {"type": "json_schema",
                                       "json_schema": {"name": "investigation_brief", "schema": schema,
                                                       "strict": True}}
        else:
            body["response_format"] = {"type": "json_object"}
        auth = f"Bearer {self.api_key}" if self.auth_header == "Authorization" else self.api_key
        data = await post_json_with_backoff(f"{self.base_url}/chat/completions",
                                            headers={self.auth_header: auth}, body=body, timeout=self.timeout,
                                            max_retries=1)
        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise ProviderError(f"unexpected response: {str(data)[:200]}") from exc
        return NarrativeResult(self.name, self.model, _parse_json(text),
                               round((time.perf_counter() - t0) * 1000, 1), text)


def groq_provider(api_key: str, model: str, timeout: float) -> OpenAICompatibleProvider:
    """Groq free plan: 8K tokens/minute per model, so the evidence pack is budgeted (~3.5K input tokens)
    and GPT-OSS reasoning is kept short. Strict JSON-schema mode is supported for gpt-oss-20b/120b."""
    extra: dict[str, Any] = {"max_completion_tokens": 2000}
    if "gpt-oss" in model:
        extra["reasoning_effort"] = "low"
    return OpenAICompatibleProvider("groq", "https://api.groq.com/openai/v1", api_key, model, timeout,
                                    extra_body=extra, max_pack_chars=8000)


def mercury_provider(api_key: str, model: str, timeout: float, reasoning_effort: str = "low"
                     ) -> OpenAICompatibleProvider:
    """Inception Labs Mercury diffusion LLM: OpenAI-compatible, strict JSON-schema structured outputs,
    260K context and free-tier limits of 1M input tokens/min, so the full evidence pack is sent."""
    return OpenAICompatibleProvider("mercury", "https://api.inceptionlabs.ai/v1", api_key, model, timeout,
                                    extra_body={"reasoning_effort": reasoning_effort})


def foundry_provider(endpoint: str, api_key: str, deployment: str, timeout: float) -> OpenAICompatibleProvider:
    """Microsoft Foundry / Azure OpenAI v1-compatible endpoint, e.g.
    https://<resource>.openai.azure.com/openai/v1  (api-key header, model = deployment name)."""
    return OpenAICompatibleProvider("foundry", endpoint, api_key, deployment, timeout, auth_header="api-key")
