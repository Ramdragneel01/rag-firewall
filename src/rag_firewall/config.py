"""Application configuration loaded from environment variables."""
from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for rag-firewall.

    All variables are prefixed with ``RAGFW_`` and read from the environment
    or a local ``.env`` file.
    """

    model_config = SettingsConfigDict(
        env_prefix="RAGFW_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    upstream_base_url: str = Field(default="https://api.openai.com")
    upstream_api_key: str = Field(default="")

    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8080)
    log_level: str = Field(default="INFO")

    enable_input_scanner: bool = Field(default=True)
    enable_output_scanner: bool = Field(default=True)
    enable_tool_allowlist: bool = Field(default=True)

    injection_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    tool_allowlist: List[str] = Field(default_factory=list)

    otel_exporter_otlp_endpoint: str = Field(default="")
    service_name: str = Field(default="rag-firewall")

    @field_validator("tool_allowlist", mode="before")
    @classmethod
    def _split_csv(cls, v):
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
