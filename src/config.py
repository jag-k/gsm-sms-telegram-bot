import logging
import re
import tomllib

from functools import lru_cache
from pathlib import Path
from typing import Literal

import logfire

from logfire.integrations.httpx import RequestInfo
from opentelemetry.trace import Span
from pydantic import AnyHttpUrl, BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


_default_log_level = logging.WARNING  # Default logging level for non-project modules
logging.basicConfig(
    format="%(asctime)s - %(levelname)s [%(name)s]: %(message)s",
    level=_default_log_level,
)


SRC_DIR = Path(__file__).resolve().parent
BASE_DIR = SRC_DIR.parent
DATA_DIR = BASE_DIR / "data"
DOCKER_DATA_DIR = Path("/data")
PERSISTENCE_FILE_NAME = "sms_bot_data.pickle"

_project_info = tomllib.loads(Path(BASE_DIR, "pyproject.toml").read_text())["project"]
PROJECT_NAME = _project_info["name"]
PROJECT_VERSION = _project_info["version"]
PROJECT_REPO = _project_info.get("urls", {}).get("Homepage", "")


def is_running_in_docker() -> bool:
    # Check for the presence of the .dockerenv file
    if Path("/.dockerenv").exists():
        return True

    # Check for the presence of 'docker' in the cgroup file
    try:
        with Path("/proc/self/cgroup").open() as f:
            for line in f:
                if "docker" in line:
                    return True
    except FileNotFoundError:
        pass

    return False


if is_running_in_docker():
    DATA_DIR = DOCKER_DATA_DIR


class BotSettings(BaseModel):
    """Settings for the SMS Telegram Bot."""

    token: str = Field(..., description="Telegram Bot API token")
    allowed_user_id: int = Field(..., description="Telegram user ID that can interact with the bot")
    recent_messages_count: int = Field(10, description="Number of recent messages to show with `/start` command")

    # Persistence settings
    persistence_file: Path = Field(
        DATA_DIR / PERSISTENCE_FILE_NAME,
        description=(
            f"File to store bot persistence data. In Docker, the default is `{DOCKER_DATA_DIR / PERSISTENCE_FILE_NAME}`"
        ),
    )


class ModemSettings(BaseModel):
    """Settings for access to the GSM SMS gateway."""

    gateway_url: AnyHttpUrl = Field(AnyHttpUrl("http://127.0.0.1:8000"), description="Base URL of gsm-sms-gateway")
    default_region: str = Field("US", description="Default region code for phone numbers without country code")


class LogfireSettings(BaseModel):
    """Settings for Logfire."""

    token: str | None = Field(None, description="Logfire API token")
    environment: Literal["local", "production"] = Field("local", description="Logfire environment name")
    revision: str = Field("main", description="Git revision. Branch name or commit hash.")


class Settings(BaseSettings):
    """
    Settings for the SMS Telegram Bot.

    All settings can be overridden with environment variables.
    """

    model_config = SettingsConfigDict(
        env_file=(".env", BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        env_nested_delimiter="__",
    )

    log_level: logfire.LevelName = Field("info", description="Logging level")

    bot: BotSettings = Field(default_factory=BotSettings, description="Settings for the SMS Telegram Bot")
    modem: ModemSettings = Field(default_factory=ModemSettings, description="Settings for the GSM Modem")
    logfire: LogfireSettings = Field(default_factory=LogfireSettings, description="Settings for Logfire")


_TELEGRAM_BOT_PATH_RE = re.compile(r"/bot[^/]+/")


def _redact_httpx_request_url(span: Span, request: RequestInfo) -> None:
    """Remove Telegram bot tokens from HTTP client telemetry before export."""
    url = str(request.url)
    redacted_url = _TELEGRAM_BOT_PATH_RE.sub("/bot[redacted]/", url)
    if redacted_url == url:
        return

    span.update_name(f"{request.method.decode()} api.telegram.org/bot[redacted]")
    span.set_attributes(
        {
            "url.full": redacted_url,
            "http.url": redacted_url,
            "http.target": "/bot[redacted]",
        },
    )


async def _redact_async_httpx_request_url(span: Span, request: RequestInfo) -> None:
    """Async wrapper required by the HTTPX async instrumentation hook."""
    _redact_httpx_request_url(span, request)


def configure_logfire(settings: Settings) -> None:
    """Configure Logfire and logging based on the provided settings."""

    logfire.configure(
        local=settings.logfire.environment == "local",
        send_to_logfire="if-token-present",
        token=settings.logfire.token,
        service_name=PROJECT_NAME,
        min_level=settings.log_level,
        service_version=PROJECT_VERSION,
        environment=settings.logfire.environment,
        console=False,
        code_source=logfire.CodeSource(
            repository=PROJECT_REPO,
            revision=settings.logfire.revision,
        )
        if PROJECT_REPO
        else None,
    )

    logging.getLogger().addHandler(logfire.LogfireLoggingHandler())
    logging.getLogger("bot").setLevel(settings.log_level.upper())
    logging.getLogger("gsm_sms").setLevel(settings.log_level.upper())

    logfire.instrument_system_metrics()
    logfire.instrument_httpx(
        capture_all=False,
        capture_headers=False,
        capture_request_body=False,
        capture_response_body=False,
        async_request_hook=_redact_async_httpx_request_url,
        request_hook=_redact_httpx_request_url,
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    # noinspection PyArgumentList
    settings = Settings()
    configure_logfire(settings)
    return settings
