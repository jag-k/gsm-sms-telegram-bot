import asyncio
import logging
import re

import logfire

from sms_reader.consts import (
    CONTACT_REGEX,
    MODEM_WATCHDOG_INTERVAL,
    MODEM_WATCHDOG_TIMEOUT,
    NETWORK_REGISTRATION_RETRIES,
    NETWORK_REGISTRATION_RETRY_DELAY,
    SIM_RANGE_REGEX,
)
from sms_reader.models import ModemStatus, now_utc
from sms_reader.transport import ModemConnectionLostError, ModemTransport


logger = logging.getLogger(__name__)


class ModemController:
    """Modem lifecycle: setup, status checks, watchdog, SIM contacts."""

    def __init__(
        self,
        transport: ModemTransport,
        network_registration_retries: int = NETWORK_REGISTRATION_RETRIES,
        network_registration_retry_delay: float = NETWORK_REGISTRATION_RETRY_DELAY,
    ) -> None:
        """Initialise the controller.

        :param transport: Underlying serial transport
        :param network_registration_retries: Number of attempts to wait for network registration
        :param network_registration_retry_delay: Seconds between network registration checks
        """
        self._transport = transport
        self._network_registration_retries = network_registration_retries
        self._network_registration_retry_delay = network_registration_retry_delay

        self.contacts: dict[str, str] = {}
        self.status: ModemStatus = ModemStatus(
            sim_ready=False,
            network_registered=False,
            signal_strength=0,
        )
        self.is_initialized: bool = False
        self._last_watchdog_ping = now_utc()

    @logfire.instrument("Setup: Check Modem Status")
    async def check_modem_status(self) -> ModemStatus:
        """Check SIM card status, network registration, and signal strength."""
        status = ModemStatus(
            sim_ready=False,
            network_registered=False,
            signal_strength=0,
        )

        sim_response = await self._transport.send_at_command("AT+CPIN?")
        if sim_response.success and "READY" in sim_response.raw_response:
            status.sim_ready = True

        net_response = await self._transport.send_at_command("AT+CREG?")
        if net_response.success:
            match = re.search(r"\+CREG: \d,(\d)", net_response.raw_response)
            if match and match.group(1) in ["1", "5"]:
                status.network_registered = True

        signal_response = await self._transport.send_at_command("AT+CSQ")
        if signal_response.success:
            match = re.search(r"\+CSQ: (\d+),", signal_response.raw_response)
            if match:
                status.signal_strength = int(match.group(1))

        self.status = status
        return status

    @logfire.instrument("Setup: Configure Modem")
    async def setup(self) -> bool:
        """Configure the modem for SMS reception.

        :return: True if setup succeeded, False otherwise
        """
        if not await self._transport.connect():
            logger.error("Failed to connect to modem")
            return False

        logger.info("Initializing modem - checking status and sending basic commands")

        await self._transport.send_at_command("AT", delay=0.0, response_wait_time=1.0)
        await asyncio.sleep(2.0)
        await self._transport._clear_input_buffer(wait_timeout=0.5)

        await self._transport.send_at_command("ATE0")
        await self._transport.send_at_command("AT+CMEE=1")

        status = await self.check_modem_status()

        if not status.sim_ready:
            logger.error("SIM card not ready")
            return False

        if not status.network_registered:
            logger.warning("Not registered to network, waiting for registration")
            for i in range(self._network_registration_retries):
                logger.info(
                    f"Waiting for network registration... (attempt {i + 1}/{self._network_registration_retries})",
                )
                await asyncio.sleep(self._network_registration_retry_delay)
                status = await self.check_modem_status()
                if status.network_registered:
                    logger.info("Network registered successfully")
                    break

            if not status.network_registered:
                logger.error("Failed to register with network after multiple attempts")
                return False

        self.is_initialized = True
        logger.info("Modem controller setup completed successfully")
        return True

    async def ensure_initialized(self, retry_interval: float) -> bool:
        """Ensure the modem is initialized, running setup if needed.

        :param retry_interval: Interval shown in the error log if setup fails
        :return: True if initialized, False if setup failed
        """
        if self.is_initialized:
            return True
        logger.warning("Modem not yet set up before monitoring! Running setup...")
        ok = await self.setup()
        if not ok:
            logger.error(f"Failed to set up modem before monitoring! Retrying after {retry_interval:.2f}s...")
        return ok

    async def run_watchdog(self) -> None:
        """Perform a watchdog ping to verify the modem is still responsive.

        :raises ModemConnectionLostError: if the modem does not respond to the AT ping
        """
        since_ping = (now_utc() - self._last_watchdog_ping).total_seconds()
        if since_ping < MODEM_WATCHDOG_INTERVAL:
            return
        ping = await self._transport.send_at_command("AT", response_wait_time=MODEM_WATCHDOG_TIMEOUT)
        if ping.success:
            self._last_watchdog_ping = now_utc()
            logger.debug("Watchdog: modem responded OK")
        else:
            raise ModemConnectionLostError("Watchdog: modem did not respond to AT ping")

    @logfire.instrument("Get SIM Contacts")
    async def get_sim_contacts(self) -> dict[str, str]:
        """Fetch all contacts stored on the SIM card."""
        await self._transport.send_at_command('AT+CPBS="SM"')
        response = await self._transport.send_at_command("AT+CPBR=?")
        range_match = SIM_RANGE_REGEX.search(response.raw_response)

        if not range_match:
            return {}

        start_index, end_index = int(range_match.group(1)), int(range_match.group(2))
        response = await self._transport.send_at_command(f"AT+CPBR={start_index},{end_index}")
        contacts: dict[str, str] = {}

        for line in response.raw_response.split("\n"):
            contact_match = CONTACT_REGEX.match(line.strip())
            if contact_match:
                contacts[contact_match.group("number")] = contact_match.group("name")

        self.contacts.update(contacts)
        return contacts
