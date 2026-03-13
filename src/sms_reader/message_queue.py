import asyncio
import datetime
import logging

import logfire

from sms_reader.models import PendingMessage, SMSMessage, now_utc


logger = logging.getLogger(__name__)


class MessageQueue:
    """Multipart SMS aggregator and delivery queue."""

    def __init__(self, merge_messages_timeout: int = 10) -> None:
        """Initialise the queue.

        :param merge_messages_timeout: Seconds to wait before flushing incomplete multipart messages.
            Set to 0 to disable merging entirely.
        """
        self._merge_timeout = merge_messages_timeout
        self._merge_enabled = merge_messages_timeout > 0
        self._pending_messages: dict[str, PendingMessage] = {}
        self._last_cleanup: datetime.datetime = now_utc()
        self._sms_queue: asyncio.Queue[SMSMessage] = asyncio.Queue()

    # ------------------------------------------------------------------
    # Internal delivery helpers
    # ------------------------------------------------------------------

    @logfire.instrument("Send SMS notification {sms.sender}")
    async def _notify_single_message(self, sms: SMSMessage) -> None:
        """Put a message into the SMS queue for consumers.

        :param sms: The SMS message to enqueue
        """
        await self._sms_queue.put(sms)
        logger.info(f"Enqueued SMS from {sms.sender} (queue size: {self._sms_queue.qsize()})")

    async def _cleanup_pending_messages(self) -> None:
        """Clean up old pending messages that are beyond the merge timeout."""
        if not self._merge_enabled:
            return

        with logfire.span("Cleanup Pending Messages"):
            now = now_utc()
            if (now - self._last_cleanup).total_seconds() < self._merge_timeout:
                return

            self._last_cleanup = now
            logger.debug("Running pending message cleanup")
            expired_senders: list[str] = []

            for sender, pending in self._pending_messages.items():
                timestamp = pending.timestamp
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=datetime.UTC)

                time_diff = (now - timestamp).total_seconds()

                if time_diff > self._merge_timeout:
                    logger.debug(f"Message from {sender} expired after {time_diff:.1f}s")

                    if pending.is_complete:
                        pending.merge_message()

                    if not pending.notified:
                        pending.notified = True
                        logger.debug("Notifying about expired/complete pending message")
                        await self._notify_single_message(pending.message)

                    expired_senders.append(sender)

                    if pending.is_complete:
                        logger.info(f"Completed multipart message from {sender}")
                    else:
                        logger.warning(
                            f"Incomplete multipart message from {sender} expired after {time_diff:.1f}s",
                        )

            for sender in expired_senders:
                del self._pending_messages[sender]

            if expired_senders:
                logger.info(f"Cleaned up {len(expired_senders)} expired pending messages")

    # ------------------------------------------------------------------
    # Public processing entry point
    # ------------------------------------------------------------------

    @logfire.instrument("Process SMS Message {sms.sender}")
    async def process_message(self, sms: SMSMessage) -> None:
        """Process a received SMS message and handle multipart assembly.

        :param sms: The SMS message to process
        """
        logger.debug(f"Processing SMS from {sms.sender}")

        if not self._merge_enabled:
            await self._notify_single_message(sms)
            return

        if sms.udh_info:
            key = f"{sms.sender}_{sms.udh_info.ref_num}"

            if key not in self._pending_messages:
                self._pending_messages[key] = pending = PendingMessage(
                    message=sms,
                    parts=[sms],
                    notified=False,
                    expected_parts=sms.udh_info.total_parts,
                )
            else:
                pending = self._pending_messages[key]
                pending.parts.append(sms)
                pending.timestamp = now_utc()

            pending.merge_message()

            if pending.is_complete and not pending.notified:
                pending.notified = True
                await self._notify_single_message(pending.message)
                logger.debug(f"UDH message {key} complete, cleaning up")
                del self._pending_messages[key]
        else:
            await self._notify_single_message(sms)

        await self._cleanup_pending_messages()

    # ------------------------------------------------------------------
    # Public queue interface
    # ------------------------------------------------------------------

    def __aiter__(self) -> "MessageQueue":
        """Return self as an async iterator over incoming SMS messages."""
        return self

    async def __anext__(self) -> SMSMessage:
        """Return the next SMS message from the queue."""
        return await self._sms_queue.get()
