import asyncio
import datetime
import logging

import logfire

from bot.handlers import register_handlers
from bot.models import StoredSMS
from bot.storage import SMSStorage
from bot.threads import ThreadManager
from bot.utils import (
    is_valid_phone_number,
    normalize_recipient,
    retry_telegram_api,
    unauthorized_response,
)
from config import get_settings
from gsm_sms.client import GatewayClient, GatewayEvent
from gsm_sms.core.events import HealthChangedEvent, IncomingSmsEvent, ModemDiagnosticEvent, SendStatusEvent
from gsm_sms.core.models import HealthState, IncomingSMS, SendRequest
from telegram import Message, Update
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    ConversationHandler,
    PicklePersistence,
)


settings = get_settings()
logger = logging.getLogger(__name__)
GATEWAY_EVENT_CURSOR_KEY = "gateway_event_cursor"


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
        self.gateway: GatewayClient | None = None

        self.application: Application | None = None
        self.threads: ThreadManager
        self.storage: SMSStorage
        self._bot_data_lock = asyncio.Lock()
        self._last_modem_health_state: str | None = None
        self.shutdown_tasks: list[asyncio.Task] = []

    async def _on_modem_health_change(self, health: HealthState) -> None:
        """Notify the owner only when modem availability changes."""
        previous = self._last_modem_health_state
        self._last_modem_health_state = health.state
        if health.state in {"starting", "recovering"}:
            return
        if health.state == "ready" and previous not in {
            "offline",
            "recovering",
            "manual_intervention_required",
        }:
            return
        if self.application is None or not settings.bot.allowed_user_id:
            return
        status = "✅ GSM modem recovered" if health.state == "ready" else "⚠️ GSM modem is unavailable"
        try:
            await retry_telegram_api(
                self.app.bot.send_message,
                chat_id=settings.bot.allowed_user_id,
                text=f"{status}. {health.detail or health.state}",
            )
        except Exception as exc:
            logger.error("Failed to send modem health notification: %s", exc, exc_info=exc)

    @property
    def app(self) -> Application:
        """
        Return the application instance, raising if not yet initialized.

        :raises RuntimeError: If the application has not been built yet.
        """
        if self.application is None:
            raise RuntimeError("Application not initialized")
        return self.application

    @logfire.instrument("Check Access")
    async def check_access(self, update: Update) -> bool:
        """
        Check if the user is authorized to use the bot.

        :param update: The update to check.
        :return: True if the user is authorized, False otherwise.
        """
        user = update.effective_user
        if not user:
            logger.warning("No user information available in the update")
            return False
        if user.id != settings.bot.allowed_user_id:
            await unauthorized_response(update)
            logger.warning(f"Unauthorized access attempt by user {user.id} ({user.username})")
            return False
        if not self.gateway:
            logger.error("GSM SMS gateway is not initialized!")
            msg = update.message
            if msg:
                await msg.reply_text("GSM SMS gateway is not initialized.")
            return False
        return True

    @logfire.instrument("SMS Received")
    async def on_sms_received(self, sms: IncomingSMS) -> bool:
        """
        Callback function for when a new SMS is received.

        :param sms: The received SMS message.
        """
        if not (self.application and settings.bot.allowed_user_id):
            logger.warning("Cannot forward SMS: missing user ID or application not initialized")
            return False

        stored_sms = StoredSMS.from_incoming(sms)
        logger.info("Received SMS in %s slot %d", sms.storage, sms.slot)

        message_text = f"📩 <b>New SMS received</b>\n\n{stored_sms.to_html()}"
        thread_id = await self.threads.get_or_create_thread(sms.sender)

        message_kwargs = {
            "chat_id": settings.bot.allowed_user_id,
            "text": message_text,
            "parse_mode": ParseMode.HTML,
        }
        if thread_id is not None:
            message_kwargs["message_thread_id"] = thread_id

        try:
            await retry_telegram_api(
                self.app.bot.send_message,
                **message_kwargs,
            )
            await self.storage.store_message(stored_sms)
        except Exception as e:
            logger.error(f"Failed to forward SMS to Telegram: {e}", exc_info=e)
            return False
        return True

    async def _handle_gateway_event(self, envelope: GatewayEvent) -> bool:
        """Process one durable event and report whether its cursor may advance."""
        event = envelope.event
        if isinstance(event, IncomingSmsEvent):
            try:
                return await self.on_sms_received(event.message)
            except Exception as exc:
                logger.error(
                    "Failed to process incoming SMS from %s slot %d: %s",
                    event.message.storage,
                    event.message.slot,
                    type(exc).__name__,
                    exc_info=exc,
                )
                return False
        if isinstance(event, HealthChangedEvent):
            await self._on_modem_health_change(event.health)
        elif isinstance(event, ModemDiagnosticEvent):
            logger.warning(
                "Modem diagnostic: kind=%s command=%s storage=%s retry=%s exception=%s",
                event.kind,
                event.command_name,
                event.storage,
                event.retry_count,
                event.exception_class,
            )
        elif isinstance(event, SendStatusEvent):
            logger.debug("Send operation %s changed to %s", event.operation.id, event.operation.status)
        return True

    async def _gateway_event_consumer(self) -> None:
        """Resume the gateway stream only after Telegram has handled each event."""
        if not self.gateway:
            logger.error("Gateway event consumer started without a client")
            return
        while True:
            cursor = int(self.app.bot_data.get(GATEWAY_EVENT_CURSOR_KEY, 0))
            async for envelope in self.gateway.events(last_event_id=cursor):
                if not await self._handle_gateway_event(envelope):
                    await asyncio.sleep(1)
                    break
                async with self._bot_data_lock:
                    self.app.bot_data[GATEWAY_EVENT_CURSOR_KEY] = envelope.id

    async def _send_status_message(self, thread_id: int | None) -> Message | None:
        """
        Send a status message in the thread when available.

        :param thread_id: The thread ID to send into.
        :return: The status message or None if skipped.
        """
        if thread_id is None:
            return None
        return await retry_telegram_api(
            self.app.bot.send_message,
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
        if not await self.check_access(update):
            return ConversationHandler.END
        if not update.message:
            return ConversationHandler.END

        normalized_phone = normalize_recipient(phone_number)
        if not is_valid_phone_number(phone_number) and not normalized_phone.lstrip("+").isdigit():
            await update.message.reply_text("Cannot send SMS to a non-numeric sender.")
            return ConversationHandler.END

        thread_id = await self.threads.get_or_create_thread(normalized_phone)

        status_message: Message | None = None
        if thread_id is not None:
            status_message = await self._send_status_message(thread_id)
            if status_message is None:
                logger.error("Failed to send status message to thread")
                return ConversationHandler.END
        elif update.message:
            status_message = await update.message.reply_text("Sending SMS, please wait...")

        try:
            if self.gateway is None:
                raise RuntimeError("GSM SMS gateway is not initialized")
            logger.info("Sending SMS operation")
            operation = await self.gateway.send(SendRequest(recipient=normalized_phone, text=message_text))
            success = operation.status == "sent"

            if success:
                logger.info(f"SMS sent successfully to {normalized_phone}")
                await _update_status_message(
                    update,
                    status_message,
                    f"✅ SMS sent successfully to {normalized_phone}",
                )

                sent_sms = StoredSMS(
                    index="outgoing",
                    sender="Me",
                    text=message_text,
                    timestamp=datetime.datetime.now(datetime.UTC),
                    is_alphanumeric=False,
                    sender_type=None,
                )
                await self.storage.store_message(sent_sms)
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

    async def _initialize_gateway(self, _: Application) -> None:
        """Initialize the HTTP/SSE gateway client."""
        try:
            with logfire.span("Setup: GSM SMS gateway"):
                self.gateway = GatewayClient(settings.modem.gateway_url)
                logger.info("GSM SMS gateway client configured")

            consumer_task = asyncio.create_task(
                self._gateway_event_consumer(),
                name="gateway_event_consumer",
            )
            self.shutdown_tasks.append(consumer_task)

        except Exception as e:
            logger.error(f"Error initializing gateway client: {e}", exc_info=e)
            if self.gateway is not None:
                await self.gateway.close()
                self.gateway = None
            await self._on_modem_health_change(
                HealthState(state="manual_intervention_required", detail=f"initialization error: {type(e).__name__}"),
            )

    @logfire.instrument("Shutdown")
    async def _shutdown(self, _: Application) -> None:
        """Clean up tasks and close the gateway client."""
        logger.info("Shutting down...")
        for task in self.shutdown_tasks:
            task.cancel()
        if self.shutdown_tasks:
            await asyncio.gather(*self.shutdown_tasks, return_exceptions=True)
        self.shutdown_tasks.clear()
        if self.gateway is not None:
            await self.gateway.close()

    def make_application(self) -> None:
        """Build the Telegram application and wire up all components."""
        persistence = PicklePersistence(
            filepath=settings.bot.persistence_file,
            single_file=True,
            update_interval=10,
        )

        self.application = (
            Application.builder()
            .token(settings.bot.token)
            .persistence(persistence)
            .post_init(self._initialize_gateway)
            .post_stop(self._shutdown)
            .connect_timeout(30.0)
            .read_timeout(30.0)
            .write_timeout(30.0)
            .build()
        )

        self.threads = ThreadManager(self.application, self._bot_data_lock)
        self.storage = SMSStorage(self.application, self._bot_data_lock)
        register_handlers(self.application, self)

    def run(self) -> None:
        """Main function to run the SMS Telegram bot."""
        if not settings.bot.token:
            logger.error("No bot_token provided in settings")
            return

        if not settings.bot.allowed_user_id:
            logger.warning("No allowed_user_id set, the bot will not respond to any user")

        self.make_application()

        for _attempt in range(2):
            try:
                self.app.run_polling(allowed_updates=Update.ALL_TYPES)
                break
            except TypeError as e:
                if "does not contain valid pickle data" not in str(e):
                    raise
                logger.warning("Failed to load persistence file, deleting and retrying")
                settings.bot.persistence_file.unlink(missing_ok=True)
                self.make_application()
