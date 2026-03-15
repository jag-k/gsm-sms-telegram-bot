from __future__ import annotations

import logging

from typing import TYPE_CHECKING

import logfire

from bot.handlers.commands import set_bot_commands
from bot.utils import is_valid_phone_number, normalize_recipient
from config import get_settings
from telegram import Update
from telegram.ext import ContextTypes, ConversationHandler


if TYPE_CHECKING:
    from bot.main import SMSBot


settings = get_settings()
logger = logging.getLogger(__name__)

WAITING_FOR_NUMBER, WAITING_FOR_MESSAGE = range(2)


class SendHandlers:
    """Handlers for the /send conversation and direct contact shares."""

    def __init__(self, bot: SMSBot) -> None:
        self._bot = bot

    @logfire.instrument("Command: /send")
    async def cmd_send(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle the /send command."""
        logger.info("Processing /send command")

        if not await self._bot.check_access(update):
            return ConversationHandler.END
        if not update.message or not update.effective_chat or context.user_data is None:
            logger.error("Invalid update object or context in send command")
            return ConversationHandler.END

        logger.debug("Setting bot commands with cancel option")
        await set_bot_commands(self._bot.app.bot, update.effective_chat.id, include_cancel=True)

        args = context.args
        logger.debug(f"Send command received with {len(args) if args else 0} arguments")

        if not args:
            logger.debug("No arguments provided, requesting phone number")
            await update.message.reply_text(
                "Please provide a phone number or short code, or forward a contact to send an SMS to.",
            )
            return WAITING_FOR_NUMBER

        if len(args) == 1:
            phone_number = normalize_recipient(args[0])
            logger.debug(f"Phone number provided: {phone_number}, waiting for message")
            context.user_data["send_to_number"] = phone_number
            await update.message.reply_text(f"Please enter the message to send to {phone_number}:")
            return WAITING_FOR_MESSAGE

        phone_number = normalize_recipient(args[0])
        message_text = " ".join(args[1:])
        logger.info(f"Full SMS command received for {phone_number}")

        result = await self._bot.send_sms(update, phone_number, message_text)
        logger.debug("Removing cancel command after send operation")
        await set_bot_commands(self._bot.app.bot, update.effective_chat.id, include_cancel=False)

        return result

    @logfire.instrument("Command: /cancel")
    async def cancel_send(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Cancel the sending conversation."""
        logger.info("Processing send cancellation")

        if not update.message or not update.effective_chat or context.user_data is None:
            logger.error("Invalid update object in cancel operation")
            return ConversationHandler.END

        await update.message.reply_text("SMS sending cancelled.")

        if "send_to_number" in context.user_data:
            logger.debug("Clearing stored phone number from user data")
            del context.user_data["send_to_number"]

        logger.debug("Removing cancel command from menu")
        await set_bot_commands(self._bot.app.bot, update.effective_chat.id, include_cancel=False)

        logger.info("Send operation cancelled successfully")
        return ConversationHandler.END

    @logfire.instrument("Handle: Contact")
    async def handle_contact(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle a contact message during sending conversation."""
        logger.info("Processing contact message")

        if not update.message or not update.message.contact or context.user_data is None:
            logger.error("Invalid contact message received")
            return ConversationHandler.END

        contact = update.message.contact
        if not contact.phone_number:
            logger.warning("Contact has no phone number")
            await update.message.reply_text("This contact doesn't have a phone number.")
            return WAITING_FOR_NUMBER

        phone_number = normalize_recipient(contact.phone_number)
        logger.debug(f"Formatted phone number: {phone_number}")

        context.user_data["send_to_number"] = phone_number

        name = " ".join(part for part in [contact.first_name, contact.last_name] if part)
        await self._bot.threads.set_phone_display_name(phone_number, name)

        logger.info(f"Contact processed: {name} ({phone_number})")
        await update.message.reply_text(f"Please enter the message to send to {name} ({phone_number}):")
        return WAITING_FOR_MESSAGE

    @logfire.instrument("Handle: Direct Contact")
    async def handle_direct_contact(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int | None:
        """
        Handle a contact message sent directly (not as part of /send command).

        :param update: The update containing the contact.
        :param context: The context for this handler.
        """
        if not await self._bot.check_access(update):
            return None
        if not update.message or not update.message.contact or context.user_data is None:
            return None

        contact = update.message.contact

        if not contact.phone_number:
            await update.message.reply_text("This contact doesn't have a phone number.")
            return None

        phone_number = normalize_recipient(contact.phone_number)
        context.user_data["send_to_number"] = phone_number

        name = " ".join(part for part in [contact.first_name, contact.last_name] if part)
        await self._bot.threads.set_phone_display_name(phone_number, name)

        await update.message.reply_text(f"Please enter the message to send to {name} ({phone_number}):")
        return WAITING_FOR_MESSAGE

    @logfire.instrument("Handle: Phone Number")
    async def handle_phone_number(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """
        Handle phone number input during the sending conversation.

        :param update: The update containing the phone number.
        :param context: The context for this handler.
        :return: The next conversation state.
        """
        if not update.message or not update.message.text or context.user_data is None:
            return ConversationHandler.END

        phone_number = update.message.text.strip()

        normalized_phone = normalize_recipient(phone_number)
        if not is_valid_phone_number(phone_number) and not normalized_phone.lstrip("+").isdigit():
            await update.message.reply_text(
                "This doesn't look like a valid phone number or short code. Please try again or use /cancel to abort.",
            )
            return WAITING_FOR_NUMBER

        phone_number = normalized_phone
        context.user_data["send_to_number"] = phone_number

        await update.message.reply_text(f"Please enter the message to send to {phone_number}:")
        return WAITING_FOR_MESSAGE

    @logfire.instrument("Handle: Message to Send")
    async def handle_message_to_send(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """
        Handle message text input during the sending conversation.

        :param update: The update containing the message text.
        :param context: The context for this handler.
        :return: The next conversation state.
        """
        if not update.message:
            return ConversationHandler.END

        message_text = update.message.text
        if not message_text:
            return ConversationHandler.END

        if not context.user_data:
            return ConversationHandler.END
        phone_number = context.user_data.get("send_to_number")

        if not phone_number:
            await update.message.reply_text("Error: No phone number found. Please start over with /send.")
            return ConversationHandler.END

        return await self._bot.send_sms(update, phone_number, message_text)
