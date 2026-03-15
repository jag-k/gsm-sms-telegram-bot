from __future__ import annotations

import logging

from typing import TYPE_CHECKING

import logfire

from bot.utils import extract_sender_from_message, normalize_recipient
from telegram import Update
from telegram.ext import ContextTypes


if TYPE_CHECKING:
    from bot.main import SMSBot


logger = logging.getLogger(__name__)


class MessageHandlers:
    """Handlers for thread messages and SMS replies."""

    def __init__(self, bot: SMSBot) -> None:
        self._bot = bot

    @logfire.instrument("Handle: Thread Message")
    async def handle_thread_message(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        """
        Handle a text message sent inside a thread.

        :param update: The update containing the message.
        :param _: Context object.
        """
        if not await self._bot.check_access(update):
            return
        if not update.message or not update.message.text:
            return

        thread_id = update.message.message_thread_id
        if thread_id is None:
            return

        phone_number = await self._bot.threads.get_phone_for_thread_id(thread_id)
        if not phone_number:
            return

        logger.info(f"Processing thread message to sender: {phone_number}")
        await self._bot.send_sms(update, phone_number, update.message.text)

    @logfire.instrument("Reply to SMS")
    async def _reply_to_sms(self, update: Update, sender: str) -> None:
        """
        Handle replying to a specific sender.

        :param update: The update containing the reply.
        :param sender: The sender identifier to reply to.
        """
        logger.debug(f"Preparing sender identifier: {sender}")
        phone_number = normalize_recipient(sender)

        if not update.message:
            logger.error("No message in update for SMS reply")
            return

        reply_text = update.message.text
        if not reply_text:
            logger.warning("Empty reply text")
            return

        logger.info(f"Sending reply SMS to {phone_number}")
        await self._bot.send_sms(update, phone_number, reply_text)

    @logfire.instrument("Handle: SMS Reply")
    async def handle_sms_reply(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle replies to SMS messages."""
        logger.info("Processing SMS reply")

        if not await self._bot.check_access(update):
            return
        if not update.message:
            logger.error("No message in update for SMS reply")
            return

        thread_id = update.message.message_thread_id
        if thread_id is not None:
            phone_number = await self._bot.threads.get_phone_for_thread_id(thread_id)
            if phone_number:
                logger.info(f"Processing thread reply to sender: {phone_number}")
                await self._reply_to_sms(update, phone_number)
                return

        replied_to = update.message.reply_to_message
        if not replied_to or not replied_to.text:
            logger.warning("Invalid reply: no original message found")
            await update.message.reply_text("Please reply to an SMS message.")
            return

        sender = extract_sender_from_message(replied_to.text)
        if not sender:
            logger.warning("Could not extract sender from original message")
            await update.message.reply_text("Could not determine the recipient from the original message.")
            return

        logger.info(f"Processing reply to sender: {sender}")
        await self._reply_to_sms(update, sender)
