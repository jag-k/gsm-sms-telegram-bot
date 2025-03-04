import asyncio
import datetime
import logging

import logfire

from bot.utils import (
    error_handler,
    extract_sender_from_message,
    format_phone_number,
    is_valid_phone_number,
    retry_telegram_api,
    settings,
    unauthorized_response,
)
from sms_reader import GSMModem, SMSMessage
from telegram import BotCommand, Update
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    PicklePersistence,
    filters,
)


logger = logging.getLogger(__name__)


# Globals
WAITING_FOR_NUMBER, WAITING_FOR_MESSAGE = range(2)


# noinspection PyAttributeOutsideInit
class SMSBot:
    def __init__(self) -> None:
        self.modem: GSMModem
        self.modem_lock = asyncio.Lock()

        self.application: Application
        self.bot_data_lock = asyncio.Lock()
        self.shutdown_tasks: list[asyncio.Task] = []

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

        # Send it to the allowed user with retry
        try:
            await retry_telegram_api(
                app.bot.send_message,
                chat_id=settings.bot.allowed_user_id,
                text=message_text,
                parse_mode=ParseMode.HTML,
            )
        except Exception as e:
            logger.error(f"Failed to forward SMS to Telegram: {e}", exc_info=e)

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
        """Clear the bot's persistence storage."""
        if not self.application:
            logger.error("Cannot clear storage: application not initialized")
            return
        bot_data = self.application.bot_data

        async with self.bot_data_lock:
            bot_data.clear()
            logger.info("Cleared bot persistence storage")

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
            await update.message.reply_text("Please provide a phone number or forward a contact to send an SMS to.")
            return WAITING_FOR_NUMBER

        elif len(args) == 1:
            phone_number = args[0]
            logger.debug(f"Phone number provided: {phone_number}, waiting for message")
            context.user_data["send_to_number"] = phone_number
            await update.message.reply_text(f"Please enter the message to send to {phone_number}:")
            return WAITING_FOR_MESSAGE

        else:
            phone_number = args[0]
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

    @staticmethod
    @logfire.instrument("Handle: Contact")
    async def handle_contact(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
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

        phone_number = format_phone_number(contact.phone_number)
        logger.debug(f"Formatted phone number: {phone_number}")

        context.user_data["send_to_number"] = phone_number

        name = contact.first_name
        if contact.last_name:
            name += f" {contact.last_name}"

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
        phone_number = format_phone_number(contact.phone_number)

        # Store the phone number in user_data
        context.user_data["send_to_number"] = phone_number

        # Ask for the message
        name = contact.first_name
        if contact.last_name:
            name += f" {contact.last_name}"

        await update.message.reply_text(f"Please enter the message to send to {name} ({phone_number}):")

        # Start the conversation handler manually
        return WAITING_FOR_MESSAGE

    @staticmethod
    @logfire.instrument("Handle: Phone Number")
    async def handle_phone_number(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
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
        if not is_valid_phone_number(phone_number):
            await update.message.reply_text(
                "This doesn't look like a valid phone number. Please try again or use /cancel to abort."
            )
            return WAITING_FOR_NUMBER

        # Format the phone number
        phone_number = format_phone_number(phone_number)

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

    @logfire.instrument("Handle: SMS Reply")
    async def handle_sms_reply(self, update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle replies to SMS messages."""
        logger.info("Processing SMS reply")

        if not await self._check_access(update):
            return
        if not update.message:
            logger.error("No message in update for SMS reply")
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
        logger.debug(f"Formatting phone number for sender: {sender}")
        phone_number = format_phone_number(sender)

        if not update.message:
            logger.error("No message in update for SMS reply")
            return

        reply_text = update.message.text
        if not reply_text:
            logger.warning("Empty reply text")
            return

        logger.info(f"Sending reply SMS to {phone_number}")
        await self.send_sms(update, phone_number, reply_text)

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

        # Send a "sending" message
        status_message = await update.message.reply_text("Sending SMS, please wait...")

        try:
            # Use the lock to prevent concurrent access to the modem
            async with self.modem_lock:
                # Check if a message is long and needs to be split
                logger.info(f"Sending SMS to {phone_number}")
                success = await self.modem.send_sms(phone_number, message_text)

            if success:
                logger.info(f"SMS sent successfully to {phone_number}")
                await status_message.edit_text(f"✅ SMS sent successfully to {phone_number}")

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
                logger.error(f"Failed to send SMS to {phone_number}!")
                await status_message.edit_text(f"❌ Failed to send SMS to {phone_number}")
        except Exception as e:
            await status_message.edit_text(f"Error sending SMS: {e!s}")
            logger.error(f"SMS sending error: {e}", exc_info=e)

        return ConversationHandler.END

    @logfire.instrument("Setup: Initialize Modem")
    async def _initialize_modem(self, _: Application) -> None:
        """
        Initialize and set up the GSM modem.

        :return: True if initialization was successful, False otherwise
        """

        try:
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
            # Start SMS monitoring in a separate task
            task = asyncio.create_task(
                self.modem.run_sms_monitoring(
                    callback=self.on_sms_received,
                    lock=self.modem_lock,
                )
            )
            self.shutdown_tasks.append(task)

        except Exception as e:
            logger.error(f"Error initializing modem: {e}", exc_info=e)
            raise e from None

    @logfire.instrument("Setup: Handlers")
    def _setup_handlers(self) -> None:
        """Set up command and message handlers."""
        app = self.application
        # Command handlers
        app.add_handler(CommandHandler("start", self.cmd_start))
        app.add_handler(CommandHandler("clear", self.cmd_clear))

        # Create a conversation handler for /send command
        send_conv_handler = ConversationHandler(
            entry_points=[CommandHandler("send", self.cmd_send)],
            states={
                WAITING_FOR_NUMBER: [
                    MessageHandler(filters.CONTACT, self.handle_contact),
                    MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_phone_number),
                ],
                WAITING_FOR_MESSAGE: [
                    MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_message_to_send),
                ],
            },
            fallbacks=[CommandHandler("cancel", self.cancel_send)],
            name="send_conversation",
            persistent=True,
        )
        app.add_handler(send_conv_handler)

        # Handle direct contact shares (outside `/send` command)
        app.add_handler(MessageHandler(filters.CONTACT & ~filters.COMMAND, self.handle_direct_contact))

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

    def run(self) -> None:
        """Main function to run the SMS Telegram bot."""
        # Check if a token is provided
        if not settings.bot.token:
            logger.error("No bot_token provided in settings")
            return

        if not settings.bot.allowed_user_id:
            logger.warning("No allowed_user_id set, the bot will not respond to any user")

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
        self.application.run_polling(allowed_updates=Update.ALL_TYPES)
