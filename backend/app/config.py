from pathlib import Path
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    app_name: str = Field(default="Homenet Sentinel", alias="APP_NAME")
    app_env: str = Field(default="development", alias="APP_ENV")
    debug: bool = Field(default=True, alias="DEBUG")

    host: str = Field(default="127.0.0.1", alias="HOST")
    port: int = Field(default=8000, alias="PORT")

    database_url: str = Field(alias="DATABASE_URL")

    nmap_path: str = Field(
        default=r"C:\Program Files (x86)\Nmap\nmap.exe",
        alias="NMAP_PATH",
    )

    scan_interval_seconds: int = Field(
        default=60,
        alias="SCAN_INTERVAL_SECONDS",
    )

    default_scan_timeout_seconds: int = Field(
        default=30,
        alias="DEFAULT_SCAN_TIMEOUT_SECONDS",
    )

    local_only: bool = Field(default=True, alias="LOCAL_ONLY")

    secret_key: str = Field(
        default="CHANGE_THIS_TO_A_RANDOM_SECRET_KEY",
        alias="SECRET_KEY",
    )

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()