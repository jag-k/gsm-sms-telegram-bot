from __future__ import annotations

import logging

from typing import TYPE_CHECKING

import logfire

from bot.handlers.commands import CommandHandlers
from bot.handlers.messages import MessageHandlers
from bot.handlers.send import WAITING_FOR_MESSAGE, WAITING_FOR_NUMBER, SendHandlers
from bot.utils import error_handler
from telegram import Message
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ConversationHandler,
    MessageHandler,
    filters,
)
from telegram.ext.filters import MessageFilter


if TYPE_CHECKING:
    from bot.main import SMSBot


logger = logging.getLogger(__name__)


class _InThreadFilter(MessageFilter):
    """Filter that matches messages sent inside a forum topic thread."""

    def filter(self, message: Message) -> bool:
        return message.message_thread_id is not None


@logfire.instrument("Setup: Handlers")
def register_handlers(app: Application, bot: SMSBot) -> None:
    """
    Register all bot handlers on the application.

    :param app: The Telegram application instance.
    :param bot: The bot instance providing shared state.
    """
    cmds = CommandHandlers(bot)
    send = SendHandlers(bot)
    msgs = MessageHandlers(bot)

    app.add_handler(CommandHandler("start", cmds.cmd_start))
    app.add_handler(CommandHandler("clear", cmds.cmd_clear))
    app.add_handler(CommandHandler("rebuild", cmds.cmd_rebuild))

    send_conv_handler = ConversationHandler(
        entry_points=[CommandHandler("send", send.cmd_send)],  # ty: ignore[invalid-argument-type]
        states={  # ty: ignore[invalid-argument-type]
            WAITING_FOR_NUMBER: [
                MessageHandler(filters.CONTACT, send.handle_contact),
                MessageHandler(filters.TEXT & ~filters.COMMAND, send.handle_phone_number),
            ],
            WAITING_FOR_MESSAGE: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, send.handle_message_to_send),
            ],
        },
        fallbacks=[CommandHandler("cancel", send.cancel_send)],  # ty: ignore[invalid-argument-type]
        name="send_conversation",
        persistent=True,
    )
    app.add_handler(send_conv_handler)

    app.add_handler(MessageHandler(filters.CONTACT & ~filters.COMMAND, send.handle_direct_contact))
    app.add_handler(CallbackQueryHandler(cmds.handle_rebuild_callback, pattern=r"^rebuild_"))

    in_thread = _InThreadFilter()
    app.add_handler(
        MessageHandler(filters.TEXT & ~filters.COMMAND & ~filters.REPLY & in_thread, msgs.handle_thread_message),
        group=1,
    )
    app.add_handler(MessageHandler(filters.TEXT & filters.REPLY & ~filters.COMMAND, msgs.handle_sms_reply))

    app.add_error_handler(error_handler)
