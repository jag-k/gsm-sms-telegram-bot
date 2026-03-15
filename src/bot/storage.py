import asyncio
import logging

import logfire

from sms_reader import SMSMessage
from telegram.ext import Application


logger = logging.getLogger(__name__)


class SMSStorage:
    """Manages SMS message persistence in bot_data."""

    def __init__(self, app: Application, bot_data_lock: asyncio.Lock) -> None:
        self._app = app
        self._lock = bot_data_lock

    @logfire.instrument("Get SMS")
    async def get_messages(self) -> list[SMSMessage]:
        """
        Retrieve stored SMS messages from the bot's persistence storage.

        :return: List of stored SMS messages.
        """
        bot_data = self._app.bot_data
        bot_data.setdefault("sms_messages", [])
        async with self._lock:
            return [SMSMessage.from_dict(msg) for msg in bot_data["sms_messages"]]

    @logfire.instrument("Store SMS")
    async def store_message(self, sms: SMSMessage) -> None:
        """
        Store an SMS message in the bot's persistence storage.

        :param sms: The SMS message to store.
        """
        bot_data = self._app.bot_data
        async with self._lock:
            bot_data.setdefault("sms_messages", [])
            bot_data["sms_messages"].append(sms.to_dict())
            logger.info(f"Stored SMS from {sms.sender} in persistence storage")

    @logfire.instrument("Clear Storage")
    async def clear(self) -> None:
        """Clear stored SMS message history."""
        bot_data = self._app.bot_data
        async with self._lock:
            if "sms_messages" in bot_data:
                bot_data["sms_messages"].clear()
            else:
                bot_data["sms_messages"] = []
            logger.info("Cleared SMS message history")
