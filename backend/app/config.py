from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(str(REPO_ROOT / ".env"), ".env"), env_file_encoding="utf-8", extra="ignore"
    )

    app_env: str = "development"
    database_url: str = f"sqlite:///{REPO_ROOT / 'data' / 'sentinelmind.db'}"

    # Paid decision engine (TypeSafe Jev)
    typesafe_api_key: str = ""
    jev_model: str = "jev-latest"
    jev_benchmark_model: str = "jev-1.13.0"
    jev_timeout_seconds: float = 8.0
    jev_max_concurrency: int = 12
    jev_top_n: int = 25

    # Free narrative providers
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.8-flash"
    # Tried in order when the primary Gemini model is overloaded (503) or unavailable to the key.
    gemini_fallback_models: str = "gemini-3.1-flash-lite"
    gemini_timeout_seconds: float = 35.0
    groq_api_key: str = ""
    groq_fast_model: str = "openai/gpt-oss-20b"
    groq_hard_model: str = "openai/gpt-oss-120b"
    narrative_timeout_seconds: float = 20.0

    # Inception Labs Mercury (diffusion LLM, OpenAI-compatible)
    inception_api_key: str = ""
    inception_model: str = "mercury-2.5"
    inception_reasoning_effort: str = "instant"

    # Routing
    narrative_provider_order: str = "mercury,groq_hard,gemini,groq,template"
    prewarm_top_n: int = 3
    provider_cooldown_seconds: float = 60.0
    model_cache_enabled: bool = True

    # Optional Microsoft enhancement
    foundry_project_endpoint: str = ""
    foundry_model_deployment: str = ""
    foundry_api_key: str = ""

    # Data + pipeline
    data_dir: Path = REPO_ROOT / "data"
    mitre_catalog_path: Path = REPO_ROOT / "data" / "mitre" / "attack_catalog.json"
    correlation_window_minutes: float = 30.0
    correlation_edge_threshold: float = 0.40  # tuned on demo ground truth
    correlation_max_component: int = 300
    correlation_max_neighbors: int = 30
    risk_config_version: str = "v2-jev"
    correlation_config_version: str = "c1"
    prompt_version: str = "v2"
    demo_mode: bool = True
    demo_seed: int = 7
    max_upload_alerts: int = 50_000

    @property
    def narrative_order(self) -> list[str]:
        return [p.strip() for p in self.narrative_provider_order.split(",") if p.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
