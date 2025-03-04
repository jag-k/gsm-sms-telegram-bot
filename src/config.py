import logging
import tomllib

from functools import lru_cache
from pathlib import Path
from typing import Literal

import logfire

from pydantic import BaseModel, Field
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


def is_running_in_docker() -> bool:
    # Check for the presence of the .dockerenv file
    if Path("/.dockerenv").exists():
        return True

    # Check for the presence of 'docker' in the cgroup file
    try:
        with Path("/proc/selogfire/cgroup").open() as f:
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
    """Settings for the GSM Modem."""

    modem_port: str = Field("/dev/ttyUSB0", description="Serial port for the GSM modem")
    baud_rate: int = Field(115200, description="Baud rate for the GSM modem")
    default_region: str = Field("US", description="Default region code for phone numbers without country code")
    merge_messages_timeout: int = Field(10, description="Timeout in seconds for merging messages")
    check_rate: int = Field(3, description="Rate in seconds to check for new messages")


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


def configure_logfire(settings: Settings) -> None:
    """Configure Logfire and logging based on the provided settings."""

    logging.basicConfig(handlers=[logfire.LogfireLoggingHandler(_default_log_level)])
    logging.getLogger("bot").setLevel(settings.log_level.upper())
    logging.getLogger("sms_reader").setLevel(settings.log_level.upper())

    logfire.configure(
        local=settings.logfire.environment == "local",
        send_to_logfire="if-token-present",
        token=settings.logfire.token,
        service_name=PROJECT_NAME,
        service_version=PROJECT_VERSION,
        environment=settings.logfire.environment,
        console=logfire.ConsoleOptions(
            verbose=True,
            min_log_level=settings.log_level,
        ),
        code_source=logfire.CodeSource(
            repository="https://github.com/jag-k/gsm-sms-telegram-bot",
            revision=settings.logfire.revision,
        ),
    )
    logfire.instrument_system_metrics()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    configure_logfire(settings)
    return settings
