import asyncio
import contextlib
import datetime
import logging

from asyncio import StreamReader, StreamWriter

import logfire
import serial_asyncio

from sms_reader.consts import (
    BUFFER_CLEAR_MAX_READS,
    BUFFER_SIZE,
    MIN_SIGNIFICANT_DELAY,
)
from sms_reader.models import ATResponse, now_utc


logger = logging.getLogger(__name__)


class ModemConnectionLostError(RuntimeError):
    """Raised when the modem stops responding (watchdog failure or serial error)."""


class ModemTransport:
    """Low-level serial transport: connect, send AT commands, read responses."""

    _reader: StreamReader
    _writer: StreamWriter

    def __init__(self, port: str, baud_rate: int, response_wait_time: float) -> None:
        """Initialise transport parameters without opening the port.

        :param port: Serial port path (e.g. ``/dev/ttyUSB0``)
        :param baud_rate: Baud rate for the serial connection
        :param response_wait_time: Default seconds to wait for an AT response
        """
        self.port = port
        self.baud_rate = baud_rate
        self._response_wait_time = response_wait_time

    def _close_connection(self) -> None:
        """Close the serial connection if open."""
        writer = getattr(self, "_writer", None)
        if writer is not None:
            with contextlib.suppress(Exception):
                writer.close()
            self._writer = None  # type: ignore[assignment]

    @logfire.instrument("Setup: Connect to Modem")
    async def connect(self) -> bool:
        """Establish a connection with the modem."""
        self._close_connection()
        try:
            self._reader, self._writer = await serial_asyncio.open_serial_connection(
                url=self.port,
                baudrate=self.baud_rate,
            )
            logger.info("Connected to GSM modem.")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to modem: {e}", exc_info=e)
            return False

    async def _clear_input_buffer(
        self,
        wait_timeout: float = MIN_SIGNIFICANT_DELAY,
        max_reads: int = BUFFER_CLEAR_MAX_READS,
    ) -> None:
        """Clear any pending data in the input buffer.

        :param wait_timeout: Maximum time to wait for each read chunk
        :param max_reads: Maximum number of read attempts to prevent infinite loop on noisy modems
        """
        total_cleared = 0
        try:
            for _ in range(max_reads):
                chunk = await asyncio.wait_for(self._reader.read(BUFFER_SIZE), wait_timeout)
                if not chunk:
                    break
                total_cleared += len(chunk)
        except TimeoutError:
            pass
        if total_cleared:
            logger.debug(f"Cleared {total_cleared} bytes from input buffer")

    async def _read_response_with_deadline(self, deadline: datetime.datetime) -> tuple[str, float]:
        """Read a response until the deadline or a complete response is received.

        :param deadline: The point in time to stop waiting
        :return: The response string and elapsed time
        """
        start_time = now_utc()
        response = ""

        try:
            while now_utc() < deadline:
                chunk = await asyncio.wait_for(self._reader.read(BUFFER_SIZE), 0.5)
                if chunk:
                    response += chunk.decode(errors="ignore")
                    if "OK" in response or "ERROR" in response:
                        break
                await asyncio.sleep(0.1)
        except TimeoutError:
            pass

        elapsed = (now_utc() - start_time).total_seconds()
        return response, elapsed

    @logfire.instrument("Send AT Command {command}")
    async def send_at_command(
        self,
        command: str,
        delay: float = 0.1,
        response_wait_time: float | None = None,
    ) -> ATResponse:
        """Send an AT command and return the structured response.

        :param command: AT command to send
        :param delay: Time to wait after command before reading response
        :param response_wait_time: Maximum time to wait for response before giving up
        :return: Structured response containing success status and data
        """
        if self._writer is None:
            raise RuntimeError("Modem not connected")

        try:
            await self._clear_input_buffer()

            logger.debug(f"Sending AT command: {command}")
            self._writer.write((command + "\r\n").encode())
            await self._writer.drain()

            if delay > MIN_SIGNIFICANT_DELAY:
                await asyncio.sleep(delay)

            wait_time = response_wait_time if response_wait_time is not None else self._response_wait_time
            deadline = now_utc() + datetime.timedelta(seconds=wait_time)

            response, elapsed = await self._read_response_with_deadline(deadline)

            if not response and elapsed >= wait_time:
                logger.warning(f"Command timed out after {elapsed:.2f}s: {command}")
                return ATResponse(raw_response="", error_message=f"Command timed out: {command}")

            if "ERROR" in response:
                logger.warning(f"Command returned ERROR: {command}")
                return ATResponse(
                    raw_response=response,
                    error_message=f"Command failed: {command}",
                )

            return ATResponse(raw_response=response)

        except Exception as e:
            logger.error(f"Error sending AT command {command}: {e}", exc_info=e)
            return ATResponse(raw_response="", error_message=str(e))
