from __future__ import annotations

import asyncio
import logging

from typing import TYPE_CHECKING

import logfire
import telegram

from bot.utils import normalize_recipient, retry_telegram_api
from config import get_settings
from sms_reader import SMSMessage
from telegram import BotCommand, BotCommandScopeChat, InlineKeyboardButton, InlineKeyboardMarkup, Message, Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes


if TYPE_CHECKING:
    from bot.main import SMSBot


settings = get_settings()
logger = logging.getLogger(__name__)


@logfire.instrument("Set Bot Commands")
async def set_bot_commands(bot: telegram.Bot, chat_id: int, *, include_cancel: bool = False) -> None:
    """
    Set bot commands for the specific chat.

    :param bot: The Telegram bot instance.
    :param chat_id: The chat ID to set commands for.
    :param include_cancel: Whether to include the cancel command.
    """
    commands = [
        BotCommand("start", "Show recent SMS messages"),
        BotCommand("send", "Send an SMS message"),
        BotCommand("clear", "Clear message history"),
        BotCommand("rebuild", "Rebuild threads from history"),
    ]

    if include_cancel:
        commands.append(BotCommand("cancel", "Cancel current operation"))

    try:
        await bot.set_my_commands(commands=commands, scope=BotCommandScopeChat(chat_id=chat_id))
        logger.info(f"Bot commands set for chat {chat_id} (with cancel: {include_cancel})")
    except Exception as e:
        logger.error(f"Failed to set bot commands: {e}", exc_info=e)


class CommandHandlers:
    """Handlers for /start, /clear, /rebuild commands."""

    def __init__(self, bot: SMSBot) -> None:
        self._bot = bot

    @logfire.instrument("Command: /start")
    async def cmd_start(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle the /start command — show recent messages."""
        if not await self._bot.check_access(update):
            return
        if not update.effective_chat or not update.message:
            return

        await set_bot_commands(self._bot.app.bot, update.effective_chat.id, include_cancel=False)

        messages: list[SMSMessage] = await self._bot.storage.get_messages()
        total_messages = len(messages)

        if not messages:
            await update.message.reply_text("No SMS messages in history.")
            return

        sorted_messages = sorted(messages, key=lambda x: x.timestamp, reverse=True)
        recent_messages = sorted_messages[: settings.bot.recent_messages_count]

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

        if not await self._bot.check_access(update):
            return
        if not update.message or not update.effective_chat:
            logger.error("Invalid update object in clear command")
            return

        logger.debug("Clearing message storage")
        await self._bot.storage.clear()
        await update.message.reply_text("🧹 Message history cleared!")
        logger.info("Message history cleared successfully")

    @logfire.instrument("Command: /rebuild")
    async def cmd_rebuild(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle the /rebuild command — show confirmation before rebuilding threads."""
        logger.info("Processing /rebuild command")

        if not await self._bot.check_access(update):
            return
        if not update.message:
            return

        if not await self._bot.threads.are_topics_enabled(update.effective_chat, force_check=True):
            await update.message.reply_text("❌ Topics are not enabled for this chat. Cannot rebuild threads.")
            return

        messages = await self._bot.storage.get_messages()
        if not messages:
            await update.message.reply_text("No SMS messages in history to rebuild.")
            return

        senders: dict[str, list[SMSMessage]] = {}
        for msg in messages:
            if msg.sender == "Me":
                continue
            normalized = normalize_recipient(msg.sender)
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
    async def _execute_rebuild(self, chat: telegram.Chat | None = None) -> str:
        """
        Execute the actual thread rebuild process.

        :param chat: The chat object, used to avoid an extra ``get_chat`` API call.
        :return: HTML-formatted result summary.
        """
        if not await self._bot.threads.are_topics_enabled(chat):
            return "❌ Topics are not enabled for this chat. Cannot rebuild threads."

        messages = await self._bot.storage.get_messages()

        senders: dict[str, list[SMSMessage]] = {}
        for msg in messages:
            if msg.sender == "Me":
                continue
            normalized = normalize_recipient(msg.sender)
            senders.setdefault(normalized, []).append(msg)

        created_count = 0
        skipped_count = 0
        sent_count = 0
        failed_count = 0

        for normalized_phone, sender_msgs in senders.items():
            existing_thread_id = await self._bot.threads.get_thread_id(normalized_phone)
            if existing_thread_id is not None:
                skipped_count += 1
                continue

            thread_id = await self._bot.threads.get_or_create_thread(normalized_phone)
            if thread_id is None:
                failed_count += len(sender_msgs)
                continue

            created_count += 1

            sorted_msgs = sorted(sender_msgs, key=lambda m: m.timestamp)
            for msg in sorted_msgs:
                try:
                    await retry_telegram_api(
                        self._bot.app.bot.send_message,
                        chat_id=settings.bot.allowed_user_id,
                        text=msg.to_html(),
                        parse_mode=ParseMode.HTML,
                        message_thread_id=thread_id,
                    )
                    sent_count += 1
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
        result = await self._execute_rebuild(update.effective_chat)

        if isinstance(query.message, Message):
            await query.message.reply_text(result, parse_mode=ParseMode.HTML)
