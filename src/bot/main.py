import asyncio
import datetime
import logging
import re

import logfire
import telegram

from bot.utils import (
    error_handler,
    extract_sender_from_message,
    format_phone_number,
    is_valid_phone_number,
    retry_telegram_api,
    unauthorized_response,
)
from config import get_settings
from sms_reader import GSMModem, SMSMessage
from telegram import BotCommand, InlineKeyboardButton, InlineKeyboardMarkup, Message, Update
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    PicklePersistence,
    filters,
)
from telegram.ext.filters import MessageFilter


settings = get_settings()
logger = logging.getLogger(__name__)

# Globals
WAITING_FOR_NUMBER, WAITING_FOR_MESSAGE = range(2)
THREAD_TITLE_MAX_LENGTH = 128
_CREATING_THREAD_SENTINEL = -1


class _InThreadFilter(MessageFilter):
    """Filter that matches messages sent inside a forum topic thread."""

    def filter(self, message: Message) -> bool:
        return message.message_thread_id is not None


# noinspection PyAttributeOutsideInit
def _normalize_recipient(recipient: str) -> str:
    """
    Normalize a recipient identifier for mapping and thread naming.

    :param recipient: The phone number or sender ID.
    :return: Normalized identifier.
    """
    cleaned = recipient.strip()
    if is_valid_phone_number(cleaned):
        return format_phone_number(cleaned)
    stripped = re.sub(r"[\s\-().]", "", cleaned)
    if stripped.lstrip("+").isdigit():
        return stripped
    return cleaned


async def _update_status_message(
    update: Update,
    status_message: Message | None,
    text: str,
) -> None:
    """
    Update a status message or send a fallback reply.

    :param update: The originating update.
    :param status_message: Existing status message, if any.
    :param text: Message text to send.
    """
    if status_message:
        await status_message.edit_text(text)
        return
    if update.message:
        await update.message.reply_text(text)


class SMSBot:
    def __init__(self) -> None:
        self.modem: GSMModem
        self.modem_lock = asyncio.Lock()

        self.application: Application | None = None
        self.bot_data_lock = asyncio.Lock()
        self.topics_enabled: bool | None = None
        self.shutdown_tasks: list[asyncio.Task] = []

    async def _are_topics_enabled(self, *, force_check: bool = False) -> bool:
        """
        Check if topics are enabled for the target chat.

        :param force_check: If True, bypass the cached result and re-query the Telegram API.
        :return: True if topics are enabled, False otherwise.
        """
        if not force_check and self.topics_enabled is not None:
            return self.topics_enabled
        if not self.application:
            logger.error("Cannot check topics: application not initialized")
            self.topics_enabled = False
            return False

        try:
            chat: telegram.ChatFullInfo | None = await retry_telegram_api(
                self.application.bot.get_chat,
                chat_id=settings.bot.allowed_user_id,
            )
        except Exception as e:
            logger.warning("Failed to fetch chat info for topics check; disabling topics", exc_info=e)
            self.topics_enabled = False
            return False

        if not chat:
            logger.warning("Chat info unavailable for topics check; disabling topics")
            self.topics_enabled = False
            return False

        is_forum: bool | None = chat.is_forum
        topics_enabled = bool(is_forum)
        logger.debug("Chat %s (type=%s): is_forum=%r", chat.id, chat.type, is_forum)

        self.topics_enabled = topics_enabled
        if not topics_enabled:
            logger.warning(
                "Topics are disabled for this chat (id=%s, type=%s, is_forum=%r); falling back to General chat",
                chat.id,
                chat.type,
                is_forum,
            )
        return topics_enabled

    @staticmethod
    def _build_thread_title(phone_number: str, display_name: str | None) -> str:
        """
        Build a thread title combining the display name and identifier.

        :param phone_number: The normalized phone number or sender ID.
        :param display_name: The display name to include.
        :return: The thread title.
        """
        if not display_name:
            return phone_number
        display_name = display_name.strip()
        if not display_name:
            return phone_number

        title = f"{display_name} ({phone_number})"
        if len(title) <= THREAD_TITLE_MAX_LENGTH:
            return title

        available = THREAD_TITLE_MAX_LENGTH - len(phone_number) - 3
        if available <= 0:
            return phone_number[:THREAD_TITLE_MAX_LENGTH]

        truncated_name = display_name[:available].rstrip()
        return f"{truncated_name} ({phone_number})"

    async def _get_phone_display_name(self, normalized_phone: str) -> str | None:
        """
        Get a display name for a phone number.

        :param normalized_phone: The already-normalized phone number to look up.
        :return: The display name or None.
        """
        if not self.application:
            logger.error("Cannot access phone display names: application not initialized")
            return None
        bot_data = self.application.bot_data
        async with self.bot_data_lock:
            phone_display_names: dict[str, str] = bot_data.setdefault("phone_display_names", {})
            return phone_display_names.get(normalized_phone)

    async def _get_thread_title(self, phone_number: str) -> str:
        """
        Build a thread title for the phone number using any stored display name.

        :param phone_number: The phone number to use.
        :return: The thread title.
        """
        normalized_phone = _normalize_recipient(phone_number)
        display_name = await self._get_phone_display_name(normalized_phone)
        return self._build_thread_title(normalized_phone, display_name)

    async def _create_thread(self, normalized_phone: str) -> int | None:
        """
        Create a new thread for the normalized phone number.

        :param normalized_phone: The phone number in normalized form.
        :return: The thread ID or None if creation failed.
        """
        if not self.application:
            logger.error("Cannot create thread: application not initialized")
            return None

        try:
            thread_title = await self._get_thread_title(normalized_phone)
            topic = await retry_telegram_api(
                self.application.bot.create_forum_topic,
                chat_id=settings.bot.allowed_user_id,
                name=thread_title,
            )
        except Exception as e:
            logger.warning(f"Failed to create topic for {normalized_phone}: {e}", exc_info=e)
            return None

        if not topic:
            logger.warning(f"Topic creation returned no data for {normalized_phone}")
            return None
        thread_id = topic.message_thread_id
        if thread_id is None:
            logger.warning(f"Topic creation returned no thread id for {normalized_phone}")
            return None

        return thread_id

    async def _get_or_create_thread(self, phone_number: str) -> int | None:
        """
        Get or create a direct messages topic for a phone number.

        :param phone_number: The phone number to map to a thread.
        :return: The thread ID or None if topics are unavailable.
        """
        thread_id: int | None = None
        if not self.application:
            logger.error("Cannot create thread: application not initialized")
            return thread_id

        if not await self._are_topics_enabled():
            return thread_id

        normalized_phone = _normalize_recipient(phone_number)
        bot_data = self.application.bot_data

        async with self.bot_data_lock:
            phone_threads: dict[str, int] = bot_data.setdefault("phone_threads", {})
            thread_id = phone_threads.get(normalized_phone)

        if thread_id is not None and thread_id != _CREATING_THREAD_SENTINEL:
            return thread_id

        if thread_id == _CREATING_THREAD_SENTINEL:
            # Another coroutine is already creating a thread for this number
            return None

        # Mark as creating to prevent duplicate thread creation
        async with self.bot_data_lock:
            phone_threads[normalized_phone] = _CREATING_THREAD_SENTINEL

        thread_id = await self._create_thread(normalized_phone)

        async with self.bot_data_lock:
            if thread_id is None:
                # Creation failed, remove the sentinel
                phone_threads.pop(normalized_phone, None)
            else:
                phone_threads[normalized_phone] = thread_id
                thread_phones: dict[int, str] = bot_data.setdefault("thread_phones", {})
                thread_phones[thread_id] = normalized_phone

        return thread_id

    @logfire.instrument("SMS Received")
    async def on_sms_received(self, sms: SMSMessage) -> None:
        """
        Callback function for when a new SMS is received.

        :param sms: The received SMS message
        """
        app = self.application
        if not (app and settings.bot.allowed_user_id):
            logger.warning("Cannot forward SMS: missing user ID or application not initialized")
            return

        # Store the message in bot_data for history
        await self.store_sms_message(sms)
        logger.info(f"Received SMS from {sms.sender}: {sms.text[:50]}")

        # Format the message
        message_text = f"📩 <b>New SMS received</b>\n\n{sms.to_html()}"

        thread_id = await self._get_or_create_thread(sms.sender)

        # Send it to the allowed user with retry
        message_kwargs = {
            "chat_id": settings.bot.allowed_user_id,
            "text": message_text,
            "parse_mode": ParseMode.HTML,
        }
        if thread_id is not None:
            message_kwargs["message_thread_id"] = thread_id

        try:
            await retry_telegram_api(
                app.bot.send_message,
                **message_kwargs,
            )
        except Exception as e:
            logger.error(f"Failed to forward SMS to Telegram: {e}", exc_info=e)

    async def _sms_consumer(self) -> None:
        """Consume SMS messages from the modem queue and forward them to Telegram."""
        if not self.modem:
            logger.error("SMS consumer started without a modem instance")
            return
        async for sms in self.modem:
            await self.on_sms_received(sms)

    @logfire.instrument("Get SMS")
    async def get_sms_messages(self) -> list[SMSMessage]:
        """
        Retrieve stored SMS messages from the bot's persistence storage.

        :return: List of stored SMS messages
        """
        if not self.application:
            logger.error("Cannot retrieve SMS: application not initialized")
            return []
        bot_data = self.application.bot_data
        bot_data.setdefault("sms_messages", [])
        async with self.bot_data_lock:
            return [SMSMessage.from_dict(msg) for msg in bot_data["sms_messages"]]

    @logfire.instrument("Store SMS")
    async def store_sms_message(self, sms: SMSMessage) -> None:
        """
        Store an SMS message in the bot's persistence storage.

        :param sms: The SMS message to store
        """

        if not self.application:
            logger.error("Cannot store SMS: application not initialized")
            return
        bot_data = self.application.bot_data

        async with self.bot_data_lock:
            # Initialize a message list if it doesn't exist
            bot_data.setdefault("sms_messages", [])
            bot_data["sms_messages"].append(sms.to_dict())

            # Log the storage
            logger.info(f"Stored SMS from {sms.sender} in persistence storage")

    @logfire.instrument("Clear Storage")
    async def clear_storage(self) -> None:
        """Clear stored SMS message history."""
        if not self.application:
            logger.error("Cannot clear storage: application not initialized")
            return
        bot_data = self.application.bot_data

        async with self.bot_data_lock:
            if "sms_messages" in bot_data:
                bot_data["sms_messages"].clear()
            else:
                bot_data["sms_messages"] = []
            logger.info("Cleared SMS message history")

    @logfire.instrument("Set Bot Commands")
    async def set_bot_commands(self, chat_id: int, include_cancel: bool = False) -> None:
        """
        Set bot commands for the specific chat.

        :param chat_id: The chat ID to set commands for
        :param include_cancel: Weather to include the cancel command
        """
        if not self.application:
            logger.error("Cannot set commands: application not initialized")
            return

        commands = [
            BotCommand("start", "Show recent SMS messages"),
            BotCommand("send", "Send an SMS message"),
            BotCommand("clear", "Clear message history"),
            BotCommand("rebuild", "Rebuild threads from history"),
        ]

        # Add the cancel command only when needed
        if include_cancel:
            commands.append(BotCommand("cancel", "Cancel current operation"))

        try:
            # Set commands specifically for this chat
            await self.application.bot.set_my_commands(commands=commands, scope={"type": "chat", "chat_id": chat_id})
            logger.info(f"Bot commands set for chat {chat_id} (with cancel: {include_cancel})")
        except Exception as e:
            logger.error(f"Failed to set bot commands: {e}", exc_info=e)

    async def _rename_thread(self, thread_id: int, phone_number: str, display_name: str) -> None:
        """
        Rename an existing thread to include the display name.

        :param thread_id: The thread ID to rename.
        :param phone_number: The phone number in normalized form.
        :param display_name: The display name to use.
        """
        if not await self._are_topics_enabled():
            return
        if not self.application:
            logger.error("Cannot rename thread: application not initialized")
            return

        title = self._build_thread_title(phone_number, display_name)
        try:
            await retry_telegram_api(
                self.application.bot.edit_forum_topic,
                chat_id=settings.bot.allowed_user_id,
                message_thread_id=thread_id,
                name=title,
            )
        except Exception as e:
            logger.warning(f"Failed to rename thread for {phone_number}: {e}", exc_info=e)

    async def _set_phone_display_name(self, phone_number: str, display_name: str) -> None:
        """
        Store display name for a phone number and update thread title if needed.

        :param phone_number: The phone number to update.
        :param display_name: The display name to store.
        """
        cleaned_name = display_name.strip()
        if not cleaned_name:
            return
        if not self.application:
            logger.error("Cannot update phone display name: application not initialized")
            return

        normalized_phone = _normalize_recipient(phone_number)
        bot_data = self.application.bot_data

        async with self.bot_data_lock:
            phone_display_names: dict[str, str] = bot_data.setdefault("phone_display_names", {})
            phone_threads: dict[str, int] = bot_data.setdefault("phone_threads", {})
            phone_display_names[normalized_phone] = cleaned_name
            thread_id = phone_threads.get(normalized_phone)

        if thread_id is None:
            return
        await self._rename_thread(thread_id, normalized_phone, cleaned_name)

    async def _get_phone_for_thread_id(self, thread_id: int) -> str | None:
        """
        Get a phone number associated with a thread ID.

        :param thread_id: The message thread ID.
        :return: The phone number or None if not found.
        """
        if not self.application:
            logger.error("Cannot access thread mapping: application not initialized")
            return None
        bot_data = self.application.bot_data
        async with self.bot_data_lock:
            thread_phones: dict[int, str] = bot_data.setdefault("thread_phones", {})
            return thread_phones.get(thread_id)

    @logfire.instrument("Check Access")
    async def _check_access(self, update: Update) -> bool:
        """Check if the user is authorized to use the bot.

        :param update: The update to check
        :return: True if the user is authorized, False otherwise
        """
        user = update.effective_user
        if not user:
            logger.warning("No user information available in the update")
            return False
        if user.id != settings.bot.allowed_user_id:
            await unauthorized_response(update)
            logger.warning(f"Unauthorized access attempt by user {user.id} ({user.username})")
            return False
        if not self.modem:
            logger.error("GSM modem is not initialized!")
            msg = update.message
            if msg:
                await msg.reply_text("GSM modem is not initialized.")
            return False
        return True

    @logfire.instrument("Command: /start")
    async def cmd_start(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle the /start command - show recent messages."""
        # Check if this is the allowed user
        if not await self._check_access(update):
            return
        if not update.effective_chat or not update.message:
            return

        # Set commands for the user (without a cancel)
        await self.set_bot_commands(update.effective_chat.id, include_cancel=False)

        # Get messages from storage
        messages: list[SMSMessage] = await self.get_sms_messages()
        total_messages = len(messages)

        if not messages:
            await update.message.reply_text("No SMS messages in history.")
            return

        # Sort messages by timestamp (newest first)
        sorted_messages = sorted(messages, key=lambda x: x.timestamp, reverse=True)

        # Take only the most recent ones
        recent_messages = sorted_messages[: settings.bot.recent_messages_count]

        # Create response text
        logger.info(f"Showing {len(recent_messages)} of {total_messages} recent messages")
        response = (
            f"📋 <b>Recent SMS Messages</b> (showing {len(recent_messages)} of {total_messages})\n\n"
            f"{'\n\n'.join(msg.to_html() for msg in recent_messages)}"
        )

        await update.message.reply_text(response, parse_mode=ParseMode.HTML)

    @logfire.instrument("Command: /clear")
    async def cmd_clear(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle the /clear command."""
        logger.info("Processing /clear command")

        if not await self._check_access(update):
            return
        if not update.message or not update.effective_chat:
            logger.error("Invalid update object in clear command")
            return

        logger.debug("Clearing message storage")
        await self.clear_storage()
        await update.message.reply_text("🧹 Message history cleared!")
        logger.info("Message history cleared successfully")

    @logfire.instrument("Command: /rebuild")
    async def cmd_rebuild(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle the /rebuild command — show confirmation before rebuilding threads."""
        logger.info("Processing /rebuild command")

        if not await self._check_access(update):
            return
        if not update.message:
            return

        if not await self._are_topics_enabled(force_check=True):
            await update.message.reply_text("❌ Topics are not enabled for this chat. Cannot rebuild threads.")
            return

        messages = await self.get_sms_messages()
        if not messages:
            await update.message.reply_text("No SMS messages in history to rebuild.")
            return

        # Group messages by sender (skip outgoing with sender="Me")
        senders: dict[str, list[SMSMessage]] = {}
        for msg in messages:
            if msg.sender == "Me":
                continue
            normalized = _normalize_recipient(msg.sender)
            senders.setdefault(normalized, []).append(msg)

        if not senders:
            await update.message.reply_text("No incoming SMS messages in history to rebuild.")
            return

        total_msgs = sum(len(msgs) for msgs in senders.values())
        text = (
            f"🔄 <b>Rebuild threads</b>\n\n"
            f"This will create forum topics for each sender and re-send stored messages into them.\n\n"
            f"• <b>Senders:</b> {len(senders)}\n"
            f"• <b>Messages:</b> {total_msgs}\n\n"
            f"Senders with existing threads will be skipped entirely.\n"
            f"Continue?"
        )

        keyboard = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton("✅ Yes, rebuild", callback_data="rebuild_confirm"),
                    InlineKeyboardButton("❌ Cancel", callback_data="rebuild_cancel"),
                ],
            ],
        )
        await update.message.reply_text(text, parse_mode=ParseMode.HTML, reply_markup=keyboard)

    @logfire.instrument("Execute Rebuild")
    async def _execute_rebuild(self) -> str:
        """
        Execute the actual thread rebuild process.

        :return: HTML-formatted result summary.
        """
        if not await self._are_topics_enabled():
            return "❌ Topics are not enabled for this chat. Cannot rebuild threads."

        if not self.application:
            return "❌ Application not initialized."

        messages = await self.get_sms_messages()

        # Group messages by normalized sender, skip outgoing
        senders: dict[str, list[SMSMessage]] = {}
        for msg in messages:
            if msg.sender == "Me":
                continue
            normalized = _normalize_recipient(msg.sender)
            senders.setdefault(normalized, []).append(msg)

        created_count = 0
        skipped_count = 0
        sent_count = 0
        failed_count = 0

        for normalized_phone, sender_msgs in senders.items():
            # Check if a thread already exists
            existing_thread_id: int | None = None
            bot_data = self.application.bot_data
            async with self.bot_data_lock:
                phone_threads: dict[str, int] = bot_data.setdefault("phone_threads", {})
                existing_thread_id = phone_threads.get(normalized_phone)

            if existing_thread_id is not None and existing_thread_id != _CREATING_THREAD_SENTINEL:
                skipped_count += 1
                continue

            # Create a new thread
            thread_id = await self._get_or_create_thread(normalized_phone)
            if thread_id is None:
                failed_count += len(sender_msgs)
                continue

            created_count += 1

            # Sort messages by timestamp and send them
            sorted_msgs = sorted(sender_msgs, key=lambda m: m.timestamp)
            for msg in sorted_msgs:
                message_text = msg.to_html()
                try:
                    await retry_telegram_api(
                        self.application.bot.send_message,
                        chat_id=settings.bot.allowed_user_id,
                        text=message_text,
                        parse_mode=ParseMode.HTML,
                        message_thread_id=thread_id,
                    )
                    sent_count += 1
                    # Small delay to avoid rate limiting
                    await asyncio.sleep(0.5)
                except Exception as e:
                    logger.warning(f"Failed to send rebuild message for {normalized_phone}: {e}")
                    failed_count += 1

        result = (
            f"✅ <b>Rebuild complete</b>\n\n"
            f"• <b>Threads created:</b> {created_count}\n"
            f"• <b>Threads skipped (already exist):</b> {skipped_count}\n"
            f"• <b>Messages sent:</b> {sent_count}\n"
        )
        if failed_count:
            result += f"• <b>Failed:</b> {failed_count}\n"

        logger.info(f"Rebuild complete: {created_count} created, {skipped_count} skipped, {sent_count} sent")
        return result

    @logfire.instrument("Callback: Rebuild")
    async def handle_rebuild_callback(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle inline keyboard callback for /rebuild confirmation."""
        query = update.callback_query
        if not query or not query.data:
            return

        user = update.effective_user
        if not user or user.id != settings.bot.allowed_user_id:
            await query.answer("You are not authorized.", show_alert=True)
            return

        await query.answer()

        if query.data == "rebuild_cancel":
            await query.edit_message_text("🔄 Rebuild cancelled.")
            return

        if query.data != "rebuild_confirm":
            return

        await query.edit_message_text("🔄 Rebuilding threads, please wait...")
        result = await self._execute_rebuild()

        if isinstance(query.message, Message):
            await query.message.reply_text(result, parse_mode=ParseMode.HTML)

    @logfire.instrument("Command: /send")
    async def cmd_send(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle the /send command."""
        logger.info("Processing /send command")

        if not await self._check_access(update):
            return ConversationHandler.END
        if not update.message or not update.effective_chat or context.user_data is None:
            logger.error("Invalid update object or context in send command")
            return ConversationHandler.END

        logger.debug("Setting bot commands with cancel option")
        await self.set_bot_commands(update.effective_chat.id, include_cancel=True)

        args = context.args
        logger.debug(f"Send command received with {len(args) if args else 0} arguments")

        if not args:
            logger.debug("No arguments provided, requesting phone number")
            await update.message.reply_text(
                "Please provide a phone number or short code, or forward a contact to send an SMS to.",
            )
            return WAITING_FOR_NUMBER

        elif len(args) == 1:
            phone_number = _normalize_recipient(args[0])
            logger.debug(f"Phone number provided: {phone_number}, waiting for message")
            context.user_data["send_to_number"] = phone_number
            await update.message.reply_text(f"Please enter the message to send to {phone_number}:")
            return WAITING_FOR_MESSAGE

        else:
            phone_number = _normalize_recipient(args[0])
            message_text = " ".join(args[1:])
            logger.info(f"Full SMS command received for {phone_number}")

            result = await self.send_sms(update, phone_number, message_text)
            logger.debug("Removing cancel command after send operation")
            await self.set_bot_commands(update.effective_chat.id, include_cancel=False)

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
        await self.set_bot_commands(update.effective_chat.id, include_cancel=False)

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

        phone_number = _normalize_recipient(contact.phone_number)
        logger.debug(f"Formatted phone number: {phone_number}")

        context.user_data["send_to_number"] = phone_number

        name = " ".join(part for part in [contact.first_name, contact.last_name] if part)
        await self._set_phone_display_name(phone_number, name)

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
        # Check if this is the allowed user
        if not await self._check_access(update):
            return None
        if not update.message or not update.message.contact or context.user_data is None:
            return None

        contact = update.message.contact

        if not contact.phone_number:
            await update.message.reply_text("This contact doesn't have a phone number.")
            return None

        # Clean and format the phone number
        phone_number = _normalize_recipient(contact.phone_number)

        # Store the phone number in user_data
        context.user_data["send_to_number"] = phone_number

        # Ask for the message
        name = " ".join(part for part in [contact.first_name, contact.last_name] if part)
        await self._set_phone_display_name(phone_number, name)

        await update.message.reply_text(f"Please enter the message to send to {name} ({phone_number}):")

        # Start the conversation handler manually
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

        # Basic validation
        normalized_phone = _normalize_recipient(phone_number)
        if not is_valid_phone_number(phone_number) and not normalized_phone.lstrip("+").isdigit():
            await update.message.reply_text(
                "This doesn't look like a valid phone number or short code. Please try again or use /cancel to abort.",
            )
            return WAITING_FOR_NUMBER

        # Format the phone number
        phone_number = normalized_phone

        # Store the phone number in user_data
        context.user_data["send_to_number"] = phone_number

        # Ask for the message
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

        # Send the SMS
        return await self.send_sms(update, phone_number, message_text)

    @logfire.instrument("Handle: Thread Message")
    async def handle_thread_message(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        """
        Handle a text message sent inside a thread.

        :param update: The update containing the message.
        :param _: Context object.
        """
        if not await self._check_access(update):
            return
        if not update.message or not update.message.text:
            return

        thread_id = update.message.message_thread_id
        if thread_id is None:
            return

        phone_number = await self._get_phone_for_thread_id(thread_id)
        if not phone_number:
            return

        logger.info(f"Processing thread message to sender: {phone_number}")
        await self.send_sms(update, phone_number, update.message.text)

    @logfire.instrument("Handle: SMS Reply")
    async def handle_sms_reply(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle replies to SMS messages."""
        logger.info("Processing SMS reply")

        if not await self._check_access(update):
            return
        if not update.message:
            logger.error("No message in update for SMS reply")
            return

        thread_id = update.message.message_thread_id
        if thread_id is not None:
            phone_number = await self._get_phone_for_thread_id(thread_id)
            if phone_number:
                logger.info(f"Processing thread reply to sender: {phone_number}")
                await self.reply_to_sms(update, phone_number)
                return

        # Get the original message that was replied to
        replied_to = update.message.reply_to_message
        if not replied_to or not replied_to.text:
            logger.warning("Invalid reply: no original message found")
            await update.message.reply_text("Please reply to an SMS message.")
            return

        # Extract sender from the original message
        sender = extract_sender_from_message(replied_to.text)
        if not sender:
            logger.warning("Could not extract sender from original message")
            await update.message.reply_text("Could not determine the recipient from the original message.")
            return

        logger.info(f"Processing reply to sender: {sender}")
        await self.reply_to_sms(update, sender)

    @logfire.instrument("Reply to SMS")
    async def reply_to_sms(self, update: Update, sender: str) -> None:
        """Handle replying to a specific sender."""
        logger.debug(f"Preparing sender identifier: {sender}")
        phone_number = _normalize_recipient(sender)

        if not update.message:
            logger.error("No message in update for SMS reply")
            return

        reply_text = update.message.text
        if not reply_text:
            logger.warning("Empty reply text")
            return

        logger.info(f"Sending reply SMS to {phone_number}")
        await self.send_sms(update, phone_number, reply_text)

    async def _send_status_message(self, thread_id: int | None) -> Message | None:
        """
        Send a status message in the thread when available.

        :param thread_id: The thread ID to send into.
        :return: The status message or None if skipped.
        """
        if thread_id is None:
            return None
        if not self.application:
            logger.error("Cannot send status message: application not initialized")
            return None
        return await retry_telegram_api(
            self.application.bot.send_message,
            chat_id=settings.bot.allowed_user_id,
            text="Sending SMS, please wait...",
            message_thread_id=thread_id,
        )

    @logfire.instrument("Send SMS")
    async def send_sms(self, update: Update, phone_number: str, message_text: str) -> int:
        """
        Send an SMS message using the modem.

        :param update: The update that triggered this action.
        :param phone_number: The recipient's phone number.
        :param message_text: The message text to send.
        :return: ConversationHandler.END to end any active conversation.
        """
        # Check if this is the allowed user
        if not await self._check_access(update):
            return ConversationHandler.END
        if not update.message:
            return ConversationHandler.END

        normalized_phone = _normalize_recipient(phone_number)
        if not is_valid_phone_number(phone_number) and not normalized_phone.lstrip("+").isdigit():
            await update.message.reply_text("Cannot send SMS to a non-numeric sender.")
            return ConversationHandler.END

        thread_id = await self._get_or_create_thread(normalized_phone)

        status_message: Message | None = None
        if thread_id is not None:
            status_message = await self._send_status_message(thread_id)
            if status_message is None:
                logger.error("Failed to send status message to thread")
                return ConversationHandler.END
        elif update.message:
            status_message = await update.message.reply_text("Sending SMS, please wait...")

        try:
            # Use the lock to prevent concurrent access to the modem
            async with self.modem_lock:
                # Check if a message is long and needs to be split
                logger.info(f"Sending SMS to {normalized_phone}")
                success = await self.modem.send_sms(normalized_phone, message_text)

            if success:
                logger.info(f"SMS sent successfully to {normalized_phone}")
                await _update_status_message(
                    update,
                    status_message,
                    f"✅ SMS sent successfully to {normalized_phone}",
                )

                # Store the message in history
                sent_sms = SMSMessage(
                    index="outgoing",
                    sender="Me",
                    text=message_text,
                    timestamp=datetime.datetime.now(datetime.UTC),
                    is_alphanumeric=False,
                    sender_type=None,
                )
                await self.store_sms_message(sent_sms)
            else:
                logger.error(f"Failed to send SMS to {normalized_phone}!")
                await _update_status_message(
                    update,
                    status_message,
                    f"❌ Failed to send SMS to {normalized_phone}",
                )
        except Exception as e:
            await _update_status_message(update, status_message, f"Error sending SMS: {e!s}")
            logger.error(f"SMS sending error: {e}", exc_info=e)

        return ConversationHandler.END

    async def _initialize_modem(self, _: Application) -> None:
        """
        Initialize and set up the GSM modem.

        :return: True if initialization was successful, False otherwise
        """

        try:
            with logfire.span("Setup: Modem"):
                self.modem = GSMModem(
                    port=settings.modem.modem_port,
                    baud_rate=settings.modem.baud_rate,
                    merge_messages_timeout=settings.modem.merge_messages_timeout,
                    check_interval=settings.modem.check_rate,
                )
                setup_success = await self.modem.setup()

                if not setup_success:
                    logger.error("Failed to set up GSM modem")
                    raise RuntimeError("Failed to set up GSM modem")

                logger.info("GSM modem initialized successfully")
            # Start SMS monitoring (producer) in a separate task
            monitor_task = asyncio.create_task(
                self.modem.run_sms_monitoring(lock=self.modem_lock),
                name="sms_monitoring",
            )
            self.shutdown_tasks.append(monitor_task)

            # Start an SMS consumer in a separate task
            consumer_task = asyncio.create_task(
                self._sms_consumer(),
                name="sms_consumer",
            )
            self.shutdown_tasks.append(consumer_task)

        except Exception as e:
            logger.error(f"Error initializing modem: {e}", exc_info=e)
            raise e from None

    @logfire.instrument("Setup: Handlers")
    def _setup_handlers(self) -> None:
        """Set up command and message handlers."""
        app = self.application
        if app is None:
            raise ValueError("Application instance is not initialized")

        # Command handlers
        app.add_handler(CommandHandler("start", self.cmd_start))
        app.add_handler(CommandHandler("clear", self.cmd_clear))
        app.add_handler(CommandHandler("rebuild", self.cmd_rebuild))

        # Create a conversation handler for /send command
        send_conv_handler = ConversationHandler(
            entry_points=[CommandHandler("send", self.cmd_send)],  # ty: ignore[invalid-argument-type]
            states={  # ty: ignore[invalid-argument-type]
                WAITING_FOR_NUMBER: [
                    MessageHandler(filters.CONTACT, self.handle_contact),
                    MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_phone_number),
                ],
                WAITING_FOR_MESSAGE: [
                    MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message_to_send),
                ],
            },
            fallbacks=[CommandHandler("cancel", self.cancel_send)],  # ty: ignore[invalid-argument-type]
            name="send_conversation",
            persistent=True,
        )
        app.add_handler(send_conv_handler)

        # Handle direct contact shares (outside `/send` command)
        app.add_handler(MessageHandler(filters.CONTACT & ~filters.COMMAND, self.handle_direct_contact))

        # Handle /rebuild confirmation callbacks
        app.add_handler(CallbackQueryHandler(self.handle_rebuild_callback, pattern=r"^rebuild_"))

        # Handle messages inside a thread (separate a group so it doesn't block other handlers)
        in_thread = _InThreadFilter()
        app.add_handler(
            MessageHandler(filters.TEXT & ~filters.COMMAND & ~filters.REPLY & in_thread, self.handle_thread_message),
            group=1,
        )

        # Handle replies to SMS messages
        app.add_handler(MessageHandler(filters.TEXT & filters.REPLY & ~filters.COMMAND, self.handle_sms_reply))

        # Error handler
        app.add_error_handler(error_handler)

    @logfire.instrument("Shutdown")
    async def _shutdown(self, _: Application) -> None:
        """Clean up tasks and close the modem."""
        logger.info("Shutting down...")
        for task in self.shutdown_tasks:
            task.cancel()

    def make_application(self):
        # Create persistence
        persistence = PicklePersistence(
            filepath=settings.bot.persistence_file,
            single_file=True,
            update_interval=10,
        )

        # Create an application with increased timeouts
        self.application = (
            Application.builder()
            .token(settings.bot.token)
            .persistence(persistence)
            .post_init(self._initialize_modem)
            .post_stop(self._shutdown)
            .connect_timeout(30.0)  # Increase connection timeout
            .read_timeout(30.0)  # Increase read timeout
            .write_timeout(30.0)  # Increase write timeout
            .build()
        )

        # Set up handlers
        self._setup_handlers()

    def run(self) -> None:
        """Main function to run the SMS Telegram bot."""
        # Check if a token is provided
        if not settings.bot.token:
            logger.error("No bot_token provided in settings")
            return

        if not settings.bot.allowed_user_id:
            logger.warning("No allowed_user_id set, the bot will not respond to any user")

        self.make_application()
        if self.application is None:
            raise ValueError("Application instance is not initialized")

        for _attempt in range(2):
            try:
                self.application.run_polling(allowed_updates=Update.ALL_TYPES)
                break
            except TypeError as e:
                if "does not contain valid pickle data" not in str(e):
                    raise
                logger.warning("Failed to load persistence file, deleting and retrying")
                settings.bot.persistence_file.unlink(missing_ok=True)
                # Recreate application with fresh persistence
                self.make_application()
