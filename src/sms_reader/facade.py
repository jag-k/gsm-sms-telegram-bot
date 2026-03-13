import asyncio
import logging

from collections.abc import AsyncIterator

import logfire

from sms_reader.consts import (
    DEFAULT_SMS_CHECK_INTERVAL,
    NETWORK_REGISTRATION_RETRIES,
    NETWORK_REGISTRATION_RETRY_DELAY,
)
from sms_reader.message_queue import MessageQueue
from sms_reader.models import ModemStatus, SMSMessage
from sms_reader.modem import ModemController
from sms_reader.monitor import SMSMonitor
from sms_reader.sms_reader import SMSReader
from sms_reader.sms_sender import SMSSender
from sms_reader.transport import ModemTransport


logger = logging.getLogger(__name__)


class GSMModem:
    """Facade that wires together all GSM modem subsystems.

    Provides the same public API as the original monolithic class while
    delegating each concern to a dedicated object.

    Direct access to subsystems is available via attributes:

    - ``modem.transport``   — :class:`~sms_reader.transport.ModemTransport`
    - ``modem.controller``  — :class:`~sms_reader.modem.ModemController`
    - ``modem.reader``      — :class:`~sms_reader.sms_reader.SMSReader`
    - ``modem.sender``      — :class:`~sms_reader.sms_sender.SMSSender`
    - ``modem.queue``       — :class:`~sms_reader.message_queue.MessageQueue`
    - ``modem.monitor``     — :class:`~sms_reader.monitor.SMSMonitor`
    """

    def __init__(
        self,
        port: str = "/dev/ttyUSB0",
        baud_rate: int = 115200,
        merge_messages_timeout: int = 10,
        response_wait_time: float = 3.0,
        check_interval: float = DEFAULT_SMS_CHECK_INTERVAL,
        prioritize_otp: bool = True,
        network_registration_retries: int = NETWORK_REGISTRATION_RETRIES,
        network_registration_retry_delay: float = NETWORK_REGISTRATION_RETRY_DELAY,
    ) -> None:
        """Initialise all subsystems.

        :param port: Serial port where the modem is connected
        :param baud_rate: Baud rate for serial communication
        :param merge_messages_timeout: Timeout in seconds for merging multipart messages
        :param response_wait_time: Default timeout in seconds for AT commands
        :param check_interval: Interval in seconds between SMS checks
        :param prioritize_otp: Whether to prioritize OTP messages
        :param network_registration_retries: Number of attempts to wait for network registration
        :param network_registration_retry_delay: Seconds between network registration checks
        """
        self._prioritize_otp = prioritize_otp

        self.transport = ModemTransport(
            port=port,
            baud_rate=baud_rate,
            response_wait_time=response_wait_time,
        )
        self.controller = ModemController(
            transport=self.transport,
            network_registration_retries=network_registration_retries,
            network_registration_retry_delay=network_registration_retry_delay,
        )
        self.queue = MessageQueue(merge_messages_timeout=merge_messages_timeout)
        self.reader = SMSReader(
            transport=self.transport,
            queue=self.queue,
        )
        self.sender = SMSSender(transport=self.transport)
        self.monitor = SMSMonitor(
            controller=self.controller,
            reader=self.reader,
            queue=self.queue,
            check_interval=check_interval,
        )

    # ------------------------------------------------------------------
    # Delegated setup
    # ------------------------------------------------------------------

    @logfire.instrument("Setup: Configure Modem")
    async def setup(self) -> bool:
        """Configure the modem for SMS reception.

        Sets the SMS mode and loads contacts after modem initialisation.
        """
        ok = await self.controller.setup()
        if not ok:
            return False

        pdu_response = await self.transport.send_at_command("AT+CMGF=0")
        if pdu_response.success:
            self.reader.use_ucs2 = False
            self.sender.use_ucs2 = False
            logger.info("Using PDU mode for SMS reception")
        else:
            text_response = await self.transport.send_at_command("AT+CMGF=1")
            if not text_response.success:
                logger.error("Failed to set any SMS mode")
                return False
            self.reader.use_ucs2 = True
            self.sender.use_ucs2 = True
            logger.info("Using text mode for SMS reception")

        if self.reader.use_ucs2:
            await self.transport.send_at_command('AT+CSCS="UCS2"')
            await self.transport.send_at_command("AT+CSDH=1")

        await self.transport.send_at_command("AT+CNMI=0,0,0,0,0")

        logger.info("Loading contacts")
        await self.controller.get_sim_contacts()

        self.controller.is_initialized = True
        logger.info("Modem setup completed successfully")
        return True

    # ------------------------------------------------------------------
    # Convenience proxies (preserve original public API)
    # ------------------------------------------------------------------

    @property
    def port(self) -> str:
        """Serial port path."""
        return self.transport.port

    @property
    def baud_rate(self) -> int:
        """Baud rate."""
        return self.transport.baud_rate

    @property
    def status(self) -> ModemStatus:
        """Current modem status."""
        return self.controller.status

    @property
    def contacts(self) -> dict[str, str]:
        """SIM contacts."""
        return self.controller.contacts

    async def check_modem_status(self) -> ModemStatus:
        """Delegate to :meth:`ModemController.check_modem_status`."""
        return await self.controller.check_modem_status()

    async def get_sim_contacts(self) -> dict[str, str]:
        """Delegate to :meth:`ModemController.get_sim_contacts`."""
        return await self.controller.get_sim_contacts()

    async def send_sms(self, phone_number: str, message: str) -> bool:
        """Delegate to :meth:`SMSSender.send_sms`."""
        return await self.sender.send_sms(phone_number, message)

    async def send_long_sms(self, phone_number: str, message: str) -> bool:
        """Delegate to :meth:`SMSSender.send_long_sms`."""
        return await self.sender.send_long_sms(phone_number, message)

    @logfire.instrument("Delete All SMS")
    async def delete_all_sms(self) -> bool:
        """Delete all SMS messages from the modem."""
        response = await self.transport.send_at_command("AT+CMGD=1,4")
        return response.success

    async def run_sms_monitoring(
        self,
        interval: float | None = None,
        lock: asyncio.Lock | None = None,
    ) -> None:
        """Delegate to :meth:`SMSMonitor.run`.

        :param interval: Check interval in seconds (defaults to instance setting)
        :param lock: Optional lock to use for serialising modem access
        """
        await self.monitor.run(interval=interval, lock=lock)

    # ------------------------------------------------------------------
    # Async iterator — consumes from the internal queue
    # ------------------------------------------------------------------

    def __aiter__(self) -> AsyncIterator[SMSMessage]:
        """Return self as an async iterator over incoming SMS messages."""
        return self

    async def __anext__(self) -> SMSMessage:
        """Return the next SMS message from the queue."""
        return await self.queue.__anext__()
