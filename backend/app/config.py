"""Application configuration. All secrets come from environment variables."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file="../.env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "WebGuard"
    APP_ENV: str = "development"  # development | production
    SECRET_KEY: str = "change-me-in-production-use-a-long-random-value"
    DATABASE_URL: str = "sqlite:///../webguard.db"
    FRONTEND_URL: str = "http://localhost:5173"

    # Scanner safety controls
    ALLOW_PRIVATE_NETWORKS: bool = False  # True only for the local lab demo
    SCAN_TIMEOUT_SECONDS: int = 120
    SCAN_MAX_REQUESTS: int = 40
    SCAN_REQUEST_TIMEOUT: float = 10.0
    SCAN_USER_AGENT: str = "WebGuard/1.0 (authorized passive security assessment)"

    # Optional LLM analyst (OpenAI-compatible). Empty = deterministic analyst only.
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"

    # Default admin bootstrapped on first run (change immediately)
    ADMIN_EMAIL: str = "admin@webguard.local"
    ADMIN_PASSWORD: str = "webguard-admin"

    JWT_EXPIRY_HOURS: int = 24
    RATE_LIMIT_PER_MINUTE: int = 60


@lru_cache
def get_settings() -> Settings:
    return Settings()
