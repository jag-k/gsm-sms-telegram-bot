import asyncio
import datetime
import logging

from collections.abc import Awaitable, Callable

import logfire

from sms_reader.consts import (
    ACTIVE_MODE_TIMEOUT,
    DEFAULT_SMS_CHECK_INTERVAL,
    INACTIVE_MODE_THRESHOLD,
    MIN_SLEEP_INTERVAL,
    MODEM_RECOVERY_MAX_DELAY,
    SIGNIFICANT_PROCESSING_TIME,
)
from sms_reader.message_queue import MessageQueue
from sms_reader.models import SMSMessage, now_utc
from sms_reader.modem import ModemController
from sms_reader.sms_reader import SMSReader
from sms_reader.transport import ModemConnectionLostError


logger = logging.getLogger(__name__)


class SMSMonitor:
    """Polling loop that drives SMS reception: watchdog + read + adaptive interval."""

    def __init__(
        self,
        controller: ModemController,
        reader: SMSReader,
        queue: MessageQueue,
        check_interval: float = DEFAULT_SMS_CHECK_INTERVAL,
        ensure_initialized: Callable[[], Awaitable[bool]] | None = None,
    ) -> None:
        """Initialise the monitor.

        :param controller: Modem controller for initialisation and watchdog
        :param reader: SMS reader that fetches messages from the modem
        :param queue: Message queue where received messages are delivered
        :param check_interval: Base polling interval in seconds
        """
        self._controller = controller
        self._reader = reader
        self._queue = queue
        self._check_interval = check_interval
        self._ensure_initialized = ensure_initialized
        self._on_health_change: Callable[[bool, str], Awaitable[None]] | None = None
        self._is_healthy: bool | None = None

    def set_health_callback(self, callback: Callable[[bool, str], Awaitable[None]] | None) -> None:
        """Set the callback used to report availability transitions."""
        self._on_health_change = callback

    async def _report_health(self, healthy: bool, detail: str) -> None:
        """Emit state changes once, avoiding an alert for every retry."""
        previous = self._is_healthy
        self._is_healthy = healthy
        if self._on_health_change is None or previous == healthy:
            return
        if previous is None and healthy:
            return
        await self._on_health_change(healthy, detail)

    async def _ensure_modem_initialized(self, retry_interval: float) -> bool:
        """Run full setup when available, otherwise retain legacy controller setup."""
        if self._ensure_initialized is not None:
            return await self._ensure_initialized()
        return await self._controller.ensure_initialized(retry_interval)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_adaptive_interval(
        self,
        *,
        messages_count: int,
        base_interval: float,
        active_interval: float,
        max_inactive_interval: float,
        current_interval: float,
        last_message_time: datetime.datetime,
        message_activity: bool,
    ) -> tuple[float, datetime.datetime, bool]:
        """Compute the next polling interval based on recent message activity.

        :param messages_count: Number of messages received in the last check
        :param base_interval: Normal base polling interval
        :param active_interval: Short interval used right after message activity
        :param max_inactive_interval: Upper cap for the interval during long inactivity
        :param current_interval: The interval used in the previous cycle
        :param last_message_time: Timestamp of the last received message
        :param message_activity: Whether the loop is currently in "active" mode
        :return: Tuple of (new_interval, new_last_message_time, new_message_activity)
        """
        if messages_count:
            logger.info(f"Processed {messages_count} new messages")
            return active_interval, now_utc(), True

        inactive_time = (now_utc() - last_message_time).total_seconds()

        if message_activity and inactive_time > ACTIVE_MODE_TIMEOUT:
            logger.debug("Returning to base polling interval")
            return base_interval, last_message_time, False

        if not message_activity and inactive_time > INACTIVE_MODE_THRESHOLD:
            new_interval = min(current_interval * 1.2, max_inactive_interval)
            logger.debug(f"Adjusting polling interval to {new_interval:.1f}s")
            return new_interval, last_message_time, message_activity

        return current_interval, last_message_time, message_activity

    async def _run_single_check(
        self,
        lock: asyncio.Lock,
        base_interval: float,
        sms_reader_fn: Callable[[], Awaitable[list[SMSMessage]]],
    ) -> list[SMSMessage] | None:
        """Execute one SMS poll cycle: initialise, watchdog, read.

        :param lock: Shared lock that serialises modem access
        :param base_interval: Base interval used in error-retry log messages
        :param sms_reader_fn: Callable that reads SMS messages from the modem
        :return: List of messages read, or None if a recoverable connection error occurred
        """
        try:
            async with lock:
                if not await self._ensure_modem_initialized(base_interval):
                    await self._report_health(False, "modem setup did not complete")
                    return None
                await self._controller.run_watchdog()
                messages = await sms_reader_fn()
                if self._controller._transport.last_error:
                    raise ModemConnectionLostError(self._controller._transport.last_error)
                return messages
        except ModemConnectionLostError as e:
            logger.critical(f"Modem connection lost: {e} — reconnecting after {base_interval:.1f}s")
            self._controller.is_initialized = False
            self._controller._transport._close_connection()
            await self._report_health(False, str(e))
            return None
        except OSError as e:
            logger.error(f"Serial I/O error: {e} — reconnecting after {base_interval:.1f}s")
            self._controller.is_initialized = False
            self._controller._transport._close_connection()
            await self._report_health(False, str(e))
            return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(
        self,
        interval: float | None = None,
        lock: asyncio.Lock | None = None,
    ) -> None:
        """Start monitoring for new SMS messages, placing them into the queue.

        Consume messages via ``async for sms in monitor.queue`` or
        ``await monitor.queue._sms_queue.get()``.

        :param interval: Check interval in seconds (defaults to instance setting)
        :param lock: Optional lock to use for serialising modem access
        """
        if not lock:
            lock = asyncio.Lock()
        if not interval:
            interval = self._check_interval

        max_inactive_interval = min(interval * 2, 5.0)
        active_interval = max(0.5, interval / 2)
        current_interval = interval
        last_message_time = now_utc()
        message_activity = False
        recovery_failures = 0

        sms_reader_fn = self._reader.read_sms_pdu if not self._reader.use_ucs2 else self._reader.read_sms_text

        logger.info(f"Starting SMS monitoring with base interval of {interval:.1f}s")
        logger.info(f"Using active interval: {active_interval:.1f}s, max interval: {max_inactive_interval:.1f}s")

        while True:
            check_start = now_utc()

            with logfire.span("Check for New Messages"):
                messages = await self._run_single_check(lock, interval, sms_reader_fn)

                if messages is None:
                    recovery_failures += 1
                    recovery_delay = min(
                        interval * 2 ** min(recovery_failures, 7),
                        MODEM_RECOVERY_MAX_DELAY,
                    )
                    logger.warning(
                        f"Modem unavailable; retrying full setup in {recovery_delay:.1f}s "
                        f"(attempt {recovery_failures})",
                    )
                    await asyncio.sleep(recovery_delay)
                    continue

                await self._report_health(True, "modem responded and SMS monitoring resumed")
                recovery_failures = 0

                current_interval, last_message_time, message_activity = self._compute_adaptive_interval(
                    messages_count=len(messages),
                    base_interval=interval,
                    active_interval=active_interval,
                    max_inactive_interval=max_inactive_interval,
                    current_interval=current_interval,
                    last_message_time=last_message_time,
                    message_activity=message_activity,
                )

                elapsed = (now_utc() - check_start).total_seconds()
                sleep_time = max(MIN_SLEEP_INTERVAL, current_interval - elapsed)

                if elapsed > SIGNIFICANT_PROCESSING_TIME:
                    logger.debug(f"SMS check took {elapsed:.2f}s, sleeping {sleep_time:.2f}s")

                await asyncio.sleep(sleep_time)
