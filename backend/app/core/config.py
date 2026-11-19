"""Application configuration.

Loaded from environment / .env via pydantic-settings. Secrets never appear in
source (SR-STORE-06). The app refuses to boot, in every environment, without
a strong SECRET_KEY (SR-STORE-09, DD-05): failing to start is better than
starting with a signing key anyone can read.
"""

from __future__ import annotations

import functools
from pathlib import Path

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.utils.validators import parse_cors_origins, validate_secret_key


class Settings(BaseSettings):
    """Typed application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        hide_input_in_errors=True,  # a rejected SECRET_KEY is never echoed
    )

    # --- Application ---
    app_env: str = "development"
    app_name: str = "Smart Home Security API"
    log_level: str = "INFO"

    # --- Security ---
    #: Required in every environment (DD-05). validate_default makes an unset
    #: value fail validation instead of silently starting with "".
    secret_key: str = Field(default="", repr=False, validate_default=True)
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = Field(default=15, ge=1, le=120)
    refresh_token_expire_days: int = Field(default=14, ge=1, le=90)

    # --- Brute-force protection (SR-AUTH-11, SR-AUTH-13, DD-05) ---
    login_ip_limit: int = Field(default=20, ge=1, le=1000)
    login_ip_window_seconds: int = Field(default=300, ge=1, le=86400)
    login_failure_limit: int = Field(default=5, ge=1, le=100)
    login_failure_window_seconds: int = Field(default=900, ge=1, le=86400)
    refresh_ip_limit: int = Field(default=60, ge=1, le=1000)
    refresh_ip_window_seconds: int = Field(default=300, ge=1, le=86400)

    # --- Database ---
    database_path: Path = Path("./data/smarthome.db")
    sqlite_busy_timeout_ms: int = Field(default=5000, ge=0, le=60000)

    # --- Locale ---
    household_timezone: str = "UTC"

    # --- CORS ---
    cors_allowed_origins: str = "http://localhost:5173"

    # --- Suspicious activity monitoring (M13) ---
    #: Findings at or above this severity notify the homeowner. LOW never does.
    notify_min_severity: str = "medium"
    #: Local quiet hours for the informational quiet-hours rule.
    monitoring_quiet_hours: str = "01:00-05:00"
    #: Findings with the same key join an open incident within this window.
    incident_merge_window_minutes: int = Field(default=30, ge=1, le=1440)
    #: Minimum gap between two notifications about the same incident.
    notification_cooldown_minutes: int = Field(default=15, ge=1, le=1440)

    # --- Notifications (M20). Secrets live only in .env (SR-STORE-06). ---
    whatsapp_enabled: bool = False
    whatsapp_access_token: str = Field(default="", repr=False)
    whatsapp_phone_number_id: str = ""
    whatsapp_api_version: str = "v25.0"
    whatsapp_template_name: str = ""
    whatsapp_template_language: str = "en"
    whatsapp_app_secret: str = Field(default="", repr=False)
    whatsapp_webhook_verify_token: str = Field(default="", repr=False)
    homeowner_whatsapp_number: str = ""
    sms_enabled: bool = False
    twilio_account_sid: str = ""
    twilio_auth_token: str = Field(default="", repr=False)
    twilio_from_number: str = ""
    homeowner_sms_number: str = ""
    #: Public HTTPS URL of POST /api/v1/notifications/webhooks/twilio, if any.
    twilio_status_callback_url: str = ""
    notification_timeout_seconds: float = Field(default=10.0, gt=0, le=60)

    @field_validator("notify_min_severity")
    @classmethod
    def _known_severity(cls, value: str) -> str:
        normalised = value.strip().lower()
        if normalised not in ("low", "medium", "high", "critical"):
            raise ValueError(
                "notify_min_severity must be low, medium, high or critical"
            )
        return normalised

    @field_validator("monitoring_quiet_hours")
    @classmethod
    def _quiet_hours(cls, value: str) -> str:
        from app.domain.suspicious_activity import parse_quiet_hours

        parse_quiet_hours(value)
        return value.strip()

    @property
    def is_production(self) -> bool:
        return self.app_env.strip().lower() == "production"

    @property
    def cors_origins(self) -> list[str]:
        """Validated allowlist. Never a wildcard (SR-STORE-19)."""
        return parse_cors_origins(
            self.cors_allowed_origins, production=self.is_production
        )

    @field_validator("secret_key")
    @classmethod
    def _require_strong_secret(cls, value: str) -> str:
        return validate_secret_key(value)

    @field_validator("jwt_algorithm")
    @classmethod
    def _reject_unsafe_algorithm(cls, value: str) -> str:
        """Block the ``alg: none`` family outright (SR-AUTH-09)."""
        allowed = {"HS256", "HS384", "HS512"}
        normalised = value.strip().upper()
        if normalised not in allowed:
            raise ValueError(
                f"jwt_algorithm must be one of {sorted(allowed)}, got {value!r}"
            )
        return normalised

    @model_validator(mode="after")
    def _validate_cors(self) -> Settings:
        """Fail at startup, not on the first request, if an origin is invalid."""
        parse_cors_origins(self.cors_allowed_origins, production=self.is_production)
        return self


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings instance (one read of the environment per process)."""
    return Settings()
