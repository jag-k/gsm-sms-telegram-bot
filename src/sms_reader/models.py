import datetime
import html
import logging

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from sms_reader.utils import now_utc


logger = logging.getLogger(__name__)


_QUALITY_MAX_VALUE = 31  # Maximum RSSI value
_QUALITY_MIN_VALUE = 0  # Minimum RSSI value
_QUALITY_EXCELLENT_THRESHOLD = 20  # RSSI value for excellent signal quality
_QUALITY_GOOD_THRESHOLD = 15  # RSSI value for good signal quality
_QUALITY_FAIR_THRESHOLD = 10  # RSSI value for fair signal quality
_QUALITY_POOR_THRESHOLD = 0  # RSSI value for poor signal quality
_QUALITY_NO_SIGNAL_VALUE = 99  # RSSI value for no signal


class SignalQuality(StrEnum):
    """Signal quality levels for GSM modem."""

    EXCELLENT = "Excellent"
    GOOD = "Good"
    FAIR = "Fair"
    POOR = "Poor"
    NO_SIGNAL = "No signal"
    UNKNOWN = "Unknown"

    @classmethod
    def from_rssi(cls, rssi: int) -> "SignalQuality":
        """Create signal quality from RSSI value."""
        if rssi == _QUALITY_NO_SIGNAL_VALUE:
            return cls.UNKNOWN
        elif rssi >= _QUALITY_EXCELLENT_THRESHOLD:  # -73 dBm or better
            return cls.EXCELLENT
        elif rssi >= _QUALITY_GOOD_THRESHOLD:  # -83 dBm or better
            return cls.GOOD
        elif rssi >= _QUALITY_FAIR_THRESHOLD:  # -93 dBm or better
            return cls.FAIR
        elif rssi > _QUALITY_POOR_THRESHOLD:
            return cls.POOR
        else:
            return cls.NO_SIGNAL

    def __bool__(self) -> bool:
        """Check if the signal quality is known."""
        return self != self.UNKNOWN


@dataclass
class ModemStatus:
    """Status information about the GSM modem."""

    sim_ready: bool
    network_registered: bool
    signal_strength: int

    @property
    def signal_quality(self) -> SignalQuality:
        """Signal quality as a SignalQuality enum."""
        return SignalQuality.from_rssi(self.signal_strength)

    def __bool__(self) -> bool:
        """Check if the modem is ready."""
        return (
            self.sim_ready
            and self.network_registered
            and _QUALITY_MIN_VALUE < self.signal_strength <= _QUALITY_MAX_VALUE
        )


@dataclass
class SMSMessage:
    """Structure representing an SMS message."""

    index: str
    sender: str
    text: str
    timestamp: datetime.datetime
    is_alphanumeric: bool
    sender_type: int | None = None  # Type of address (0x91=international, 0x81=national, 0x50/0xD0=alphanumeric)
    udh_info: dict | None = None  # UDH information for multipart messages

    @classmethod
    def from_dict(cls, data: dict) -> "SMSMessage":
        timestamp: str | datetime.datetime | None = data.pop("timestamp", None)
        if timestamp is not None:
            if isinstance(timestamp, str):
                timestamp = datetime.datetime.fromisoformat(timestamp)
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=datetime.UTC)
            data["timestamp"] = timestamp
        else:
            logger.debug(f"Timestamp is None! {data=}")

        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "sender": self.sender,
            "text": self.text,
            "timestamp": self.timestamp.isoformat(),
            "is_alphanumeric": self.is_alphanumeric,
            "sender_type": self.sender_type,
            "udh_info": self.udh_info,
        }

    def to_html(self) -> str:
        # Get system timezone
        tz_object = datetime.datetime.now().astimezone().tzinfo
        ts = self.timestamp.astimezone(tz_object)
        return (
            f"<b>From:</b> {self.sender}\n"
            f"<b>Time:</b> {ts.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"<blockquote>{html.escape(self.text)}</blockquote>"
        )


@dataclass
class PendingMessage:
    message: SMSMessage
    parts: list[SMSMessage]
    notified: bool = False  # Track if we've notified about this message
    expected_parts: int | None = None  # Number of expected parts, if known
    timestamp: datetime.datetime = field(default_factory=now_utc)


@dataclass
class ATResponse:
    """Structured response from an AT command."""

    raw_response: str
    data: Any = None
    error_message: str | None = None

    @property
    def success(self) -> bool:
        """Check if the response indicates success."""
        return "OK" in self.raw_response or not self.error_message
