import asyncio
import contextlib
import datetime
import logging

import logfire
import messaging.sms

from sms_reader.consts import (
    ASCII_SMS_LENGTH,
    BUFFER_SIZE,
    MIN_SIGNIFICANT_DELAY,
    SMS_PREVIEW_LENGTH,
    SMS_PROMPT_TIMEOUT,
    SMS_SEND_TIMEOUT,
    UNICODE_CHAR_THRESHOLD,
    UNICODE_SMS_LENGTH,
)
from sms_reader.models import now_utc
from sms_reader.transport import ModemTransport


logger = logging.getLogger(__name__)


class SMSSender:
    """Sends SMS messages via the modem in text or PDU mode."""

    def __init__(self, transport: ModemTransport, use_ucs2: bool = False) -> None:
        """Initialise the sender.

        :param transport: Underlying serial transport
        :param use_ucs2: Whether the modem is currently in UCS2 text mode
        """
        self._transport = transport
        self.use_ucs2 = use_ucs2

    # ------------------------------------------------------------------
    # Low-level I/O helpers
    # ------------------------------------------------------------------

    async def _read_until_prompt(self, wait_time: float) -> tuple[bool, str]:
        """Read modem output until the prompt character ``>`` or timeout.

        :param wait_time: Maximum time to wait for prompt
        :return: Tuple of (prompt_received, response_text)
        """
        start_time = now_utc()
        response = ""
        deadline = start_time + datetime.timedelta(seconds=wait_time)

        try:
            while now_utc() < deadline:
                chunk = await asyncio.wait_for(self._transport._reader.read(BUFFER_SIZE), 0.5)
                if chunk:
                    response += chunk.decode(errors="ignore")
                    if ">" in response:
                        elapsed = (now_utc() - start_time).total_seconds()
                        logger.debug(f"SMS prompt received in {elapsed:.2f}s")
                        return True, response
                await asyncio.sleep(0.1)
        except TimeoutError:
            pass

        return False, response

    async def _read_until_response(self, wait_time: float) -> str:
        """Read modem output until response completion or timeout.

        :param wait_time: Maximum time to wait for response
        :return: Response text
        """
        start_time = now_utc()
        response = ""
        deadline = start_time + datetime.timedelta(seconds=wait_time)

        try:
            while now_utc() < deadline:
                chunk = await asyncio.wait_for(self._transport._reader.read(BUFFER_SIZE), 0.5)
                if chunk:
                    response += chunk.decode(errors="ignore")
                    if "OK" in response or "ERROR" in response:
                        logger.debug("Complete response received")
                        break
                    await asyncio.sleep(0.2)
                await asyncio.sleep(0.1)
        except TimeoutError:
            pass

        return response.strip()

    async def _send_sms_message(self, cmd: str, message: str) -> str:
        """Send SMS message content after an AT command.

        :param cmd: The AT command to send (e.g. ``AT+CMGS="number"``)
        :param message: The message content to send
        :return: The modem response
        """
        try:
            await self._transport._clear_input_buffer(MIN_SIGNIFICANT_DELAY)

            logger.debug(f"Sending SMS command: {cmd}")
            self._transport._writer.write((cmd + "\r").encode())
            await self._transport._writer.drain()

            prompt_received, response = await self._read_until_prompt(wait_time=SMS_PROMPT_TIMEOUT)

            if not prompt_received:
                logger.error("SMS prompt '>' not received, aborting send")
                return "ERROR: No prompt received"

            logger.debug(f"Sending SMS content: {message[:SMS_PREVIEW_LENGTH]}...")
            self._transport._writer.write((message + chr(26)).encode())
            await self._transport._writer.drain()

            response = await self._read_until_response(wait_time=SMS_SEND_TIMEOUT)

            if response:
                logger.debug(f"Full SMS response: {response}")
            return response

        except Exception as e:
            logger.error(f"Error in _send_sms_message: {e}", exc_info=e)
            return "ERROR: " + str(e)

    @contextlib.asynccontextmanager
    async def _sms_mode_context(self):
        """Async context manager that restores the modem SMS mode after send operations."""
        try:
            yield
        finally:
            restore_cmd = "AT+CMGF=1" if self.use_ucs2 else "AT+CMGF=0"
            await self._transport.send_at_command(restore_cmd)

    # ------------------------------------------------------------------
    # Public send API
    # ------------------------------------------------------------------

    @logfire.instrument("Send SMS {phone_number}: Text Mode")
    async def send_sms_text(self, phone_number: str, message: str) -> bool:
        """Send an SMS message in text mode."""
        async with self._sms_mode_context():
            mode_response = await self._transport.send_at_command("AT+CMGF=1")
            if "OK" not in mode_response.raw_response:
                logger.error("Failed to switch to text mode")
                return False

            cmd = f'AT+CMGS="{phone_number}"'
            try:
                response = await self._send_sms_message(cmd, message)
                success = "+CMGS:" in response and "OK" in response and "ERROR" not in response
                if not success:
                    logger.error(f"Text SMS send failed with response: {response}")
                return success
            except Exception as e:
                logger.error(f"Error sending SMS: {e}", exc_info=e)
                return False

    @logfire.instrument("Send SMS {phone_number}: PDU Mode")
    async def send_sms_pdu(self, phone_number: str, message: str) -> bool:
        """Send an SMS message in PDU mode."""
        async with self._sms_mode_context():
            mode_response = await self._transport.send_at_command("AT+CMGF=0")
            await asyncio.sleep(0.2)
            if "OK" not in mode_response.raw_response:
                logger.error("Failed to switch to PDU mode")
                return False

            try:
                pdu = messaging.sms.SmsSubmit(phone_number, message)
                pdu_data = pdu.to_pdu()[0]
                pdu_str = pdu_data.pdu

                smsc_len = int(pdu_str[0:2], 16)
                tpdu_len = (len(pdu_str) - 2 - (smsc_len * 2)) // 2

                logger.debug(f"PDU length: {len(pdu_str)}, TPDU length: {tpdu_len}")
                logger.debug(f"PDU string: {pdu_str}")

                cmd = f"AT+CMGS={tpdu_len}"
                response = await self._send_sms_message(cmd, pdu_str)

                success = "+CMGS:" in response and "OK" in response and "ERROR" not in response
                if not success:
                    logger.error(f"SMS send failed with response: {response}")
                return success
            except Exception as e:
                logger.error(f"Error sending SMS in PDU mode: {e}", exc_info=e)
                return False

    @logfire.instrument("Send SMS {phone_number}")
    async def send_sms(self, phone_number: str, message: str) -> bool:
        """Send an SMS message using the best available method."""
        logger.info(f"Sending SMS to {phone_number}")
        try:
            if await self.send_sms_text(phone_number, message):
                return True
        except Exception as e:
            logger.debug("Text mode failed, trying PDU mode", exc_info=e)
        return await self.send_sms_pdu(phone_number, message)

    @logfire.instrument("Send Long SMS {phone_number}")
    async def send_long_sms(self, phone_number: str, message: str) -> bool:
        """Send a long SMS by splitting into multiple parts if needed.

        :param phone_number: Recipient phone number (international format with + preferred)
        :param message: Message text to send (can be longer than standard SMS length)
        :return: True if all message parts were sent successfully, False otherwise
        """
        is_unicode = any(ord(c) > UNICODE_CHAR_THRESHOLD for c in message)
        max_length = UNICODE_SMS_LENGTH if is_unicode else ASCII_SMS_LENGTH

        if len(message) <= max_length:
            return await self.send_sms(phone_number, message)

        parts = [message[i : i + max_length] for i in range(0, len(message), max_length)]
        logger.info(f"Splitting message into {len(parts)} parts (unicode={is_unicode})")

        max_retries = 2
        for i, part in enumerate(parts, 1):
            part_text = f"({i}/{len(parts)}) {part}"
            sent = False
            for attempt in range(max_retries):
                if await self.send_sms(phone_number, part_text):
                    sent = True
                    break
                logger.warning(f"Failed to send part {i}, attempt {attempt + 1}/{max_retries}")
                await asyncio.sleep(1)
            if not sent:
                logger.error(f"Failed to send part {i} of {len(parts)} after {max_retries} attempts")
                return False

        return True
