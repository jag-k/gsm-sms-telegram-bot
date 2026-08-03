"""Telegram-local models for persisted and HTML-formatted SMS history."""

import datetime
import html

from dataclasses import dataclass
from typing import Any

from gsm_sms.core.models import IncomingSMS


@dataclass(slots=True)
class StoredSMS:
    """UI history entry kept compatible with the legacy pickle representation."""

    index: str
    sender: str
    text: str
    timestamp: datetime.datetime
    is_alphanumeric: bool
    sender_type: int | None = None
    udh_info: dict[str, Any] | None = None

    @classmethod
    def from_incoming(cls, message: IncomingSMS) -> "StoredSMS":
        """Convert a core incoming model after successful consumer handling."""
        multipart = message.multipart.model_dump(mode="json") if message.multipart else None
        return cls(
            index=str(message.slot),
            sender=message.sender,
            text=message.text,
            timestamp=message.received_at,
            is_alphanumeric=message.is_alphanumeric,
            sender_type=message.sender_type,
            udh_info=multipart,
        )

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "StoredSMS":
        """Load legacy or current persisted history without mutating bot data."""
        data = dict(value)
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.datetime.fromisoformat(timestamp)
        if not isinstance(timestamp, datetime.datetime):
            timestamp = datetime.datetime.now(datetime.UTC)
        elif timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=datetime.UTC)
        data["timestamp"] = timestamp
        udh_info = data.get("udh_info")
        if udh_info is not None and not isinstance(udh_info, dict):
            data["udh_info"] = {
                "reference": getattr(udh_info, "ref_num", 0),
                "total_parts": getattr(udh_info, "total_parts", 1),
                "current_part": getattr(udh_info, "current_part", None),
            }
        return cls(**data)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the existing pickle-friendly dictionary shape."""
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
        """Render one history entry for Telegram."""
        local_timezone = datetime.datetime.now().astimezone().tzinfo
        timestamp = self.timestamp.astimezone(local_timezone)
        return (
            f"<b>From:</b> {html.escape(self.sender)}\n"
            f"<b>Time:</b> {timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"<blockquote>{html.escape(self.text)}</blockquote>"
        )
