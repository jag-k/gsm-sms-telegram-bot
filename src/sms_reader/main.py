import asyncio
import datetime
import logging
import re

from asyncio import StreamReader, StreamWriter
from collections.abc import Awaitable, Callable
from typing import Any

import logfire
import messaging.sms
import serial_asyncio

from sms_reader.consts import (
    ACTIVE_MODE_TIMEOUT,
    ASCII_SMS_LENGTH,
    BUFFER_SIZE,
    CONTACT_REGEX,
    DEFAULT_SMS_CHECK_INTERVAL,
    INACTIVE_MODE_THRESHOLD,
    MIN_SIGNIFICANT_DELAY,
    MIN_SLEEP_INTERVAL,
    SIGNIFICANT_PROCESSING_TIME,
    SIM_RANGE_REGEX,
    SMS_HEADER_REGEX,
    SMS_PREVIEW_LENGTH,
    SMS_PROMPT_TIMEOUT,
    SMS_RESPONSE_PREVIEW,
    SMS_SEND_TIMEOUT,
    UNICODE_CHAR_THRESHOLD,
    UNICODE_SMS_LENGTH,
)
from sms_reader.models import ATResponse, ModemStatus, PendingMessage, SMSMessage, now_utc
from sms_reader.utils import (
    decode_pdu,
    decode_ucs2_text,
    parse_sms_timestamp,
    parse_text_mode_response,
)


logger = logging.getLogger(__name__)


class GSMModem:
    """GSM Modem interface for handling SMS messages with proper sender ID handling."""

    _reader: StreamReader
    _writer: StreamWriter

    def __init__(
        self,
        port: str = "/dev/ttyUSB0",
        baud_rate: int = 115200,
        merge_messages_timeout: int = 10,
        response_wait_time: float = 3.0,
        check_interval: float = DEFAULT_SMS_CHECK_INTERVAL,
        prioritize_otp: bool = True,
    ):
        """Initialize the GSM modem connection parameters.

        :param port: Serial port where the modem is connected
        :param baud_rate: Baud rate for serial communication
        :param merge_messages_timeout: Timeout in seconds for merging messages
        :param response_wait_time: Default timeout in seconds for AT commands
        :param check_interval: Interval in seconds between SMS checks
        :param prioritize_otp: Whether to prioritize OTP messages
        """
        self.port = port
        self.baud_rate = baud_rate
        self._sms_reader: Callable[[], Awaitable[list[SMSMessage]]] = self.read_sms_text
        self.on_sms_received: Callable[[SMSMessage], Any] | None = None
        self.contacts: dict[str, str] = {}
        self.status: ModemStatus = ModemStatus(
            sim_ready=False,
            network_registered=False,
            signal_strength=0,
        )

        self._pending_messages: dict[str, PendingMessage] = {}
        self._merge_timeout = merge_messages_timeout
        self._last_cleanup = now_utc()
        self._merge_enabled = merge_messages_timeout > 0
        self._response_wait_time = response_wait_time
        self._check_interval = check_interval
        self._prioritize_otp = prioritize_otp

    @logfire.instrument("Setup: Connect to Modem")
    async def connect(self) -> bool:
        """Establish a connection with the modem."""
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

    async def _clear_input_buffer(self, wait_timeout: float = MIN_SIGNIFICANT_DELAY) -> None:
        """Clear any pending data in the input buffer.

        :param wait_timeout: Maximum time to wait for data
        """
        try:
            pending = await asyncio.wait_for(self._reader.read(BUFFER_SIZE), wait_timeout)
            if pending:
                logger.debug(f"Cleared {len(pending)} bytes from input buffer")
        except TimeoutError:
            pass

    async def _read_response_with_deadline(self, deadline: datetime.datetime) -> tuple[str, float]:
        """Read a response until the deadline or complete response is received.

        :param deadline: The point in time to stop waiting
        :return: The response string and elapsed time
        """
        start_time = now_utc()
        response = ""

        try:
            while now_utc() < deadline:
                # Use a fixed timeout for each read attempt
                chunk = await asyncio.wait_for(self._reader.read(BUFFER_SIZE), 0.5)
                if chunk:
                    response += chunk.decode(errors="ignore")

                    # Check if we have a complete response
                    if "OK" in response or "ERROR" in response:
                        break

                # Small sleep between reads to prevent busy-waiting
                await asyncio.sleep(0.1)

        except TimeoutError:
            # Timeout occurred during read
            pass

        # Calculate total elapsed time
        elapsed = (now_utc() - start_time).total_seconds()

        return response, elapsed

    @logfire.instrument("Send AT Command {command}")
    async def _send_at_command(
        self,
        command: str,
        delay: float = 0.1,  # Reduced default delay
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
            # Clear any pending data in the buffer
            await self._clear_input_buffer()

            # Send the command
            logger.debug(f"Sending AT command: {command}")
            self._writer.write((command + "\r\n").encode())
            await self._writer.drain()  # Ensure the command is sent

            # Only wait if the delay is significant (optimization)
            if delay > MIN_SIGNIFICANT_DELAY:
                await asyncio.sleep(delay)

            # Get actual wait time (use instance default if not provided)
            wait_time = response_wait_time if response_wait_time is not None else self._response_wait_time
            deadline = now_utc() + datetime.timedelta(seconds=wait_time)

            # Read response with proper timeout handling
            response, elapsed = await self._read_response_with_deadline(deadline)

            # Check for timeout
            if not response and elapsed >= wait_time:
                logger.warning(f"Command timed out after {elapsed:.2f}s: {command}")
                return ATResponse(raw_response="", error_message=f"Command timed out: {command}")

            # Parse the response - simplified logic
            if "ERROR" in response:
                logger.warning(f"Command returned ERROR: {command}")
                return ATResponse(
                    raw_response=response,
                    error_message=f"Command failed: {command}",
                )

            # "OK" or other responses are considered successful
            return ATResponse(raw_response=response)

        except Exception as e:
            logger.error(f"Error sending AT command {command}: {e}", exc_info=e)
            return ATResponse(raw_response="", error_message=str(e))

    @logfire.instrument("Setup: Check Modem Status")
    async def check_modem_status(self) -> ModemStatus:
        """Check SIM card status, network registration, and signal strength."""
        status = ModemStatus(
            sim_ready=False,
            network_registered=False,
            signal_strength=0,
        )

        # Check SIM card status
        sim_response = await self._send_at_command("AT+CPIN?")
        if sim_response.success and "READY" in sim_response.raw_response:
            status.sim_ready = True

        # Check network registration
        net_response = await self._send_at_command("AT+CREG?")
        if net_response.success:
            match = re.search(r"\+CREG: \d,(\d)", net_response.raw_response)
            if match and match.group(1) in ["1", "5"]:
                status.network_registered = True

        # Check signal strength
        signal_response = await self._send_at_command("AT+CSQ")
        if signal_response.success:
            match = re.search(r"\+CSQ: (\d+),", signal_response.raw_response)
            if match:
                status.signal_strength = int(match.group(1))
        self.status = status
        return status

    @logfire.instrument("Setup: Configure Modem")
    async def setup(self) -> bool:
        """Configure the modem for SMS reception with proper sender ID handling."""
        # Connect to the modem
        if not await self.connect():
            logger.error("Failed to connect to modem")
            return False

        # Create tasks for independent operations that can run in parallel
        logger.info("Initializing modem - checking status and sending basic commands")

        # Run these commands concurrently to speed up initialization
        status = await self.check_modem_status()
        await self._send_at_command('AT+CSCS="UCS2"')
        await self._send_at_command("AT+CNMI=2,1,0,0,0")

        # Check SIM readiness
        if not status.sim_ready:
            logger.error("SIM card not ready")
            return False

        # Handle network registration with optimized retry logic
        if not status.network_registered:
            logger.warning("Not registered to network, waiting for registration")
            # Try up to 5 times with shorter wait times between checks
            max_retries = 5
            for i in range(max_retries):
                logger.info(f"Waiting for network registration... (attempt {i + 1}/{max_retries})")
                await asyncio.sleep(1)
                status = await self.check_modem_status()
                if status.network_registered:
                    logger.info("Network registered successfully")
                    break

            if not status.network_registered:
                logger.error("Failed to register with network after multiple attempts")
                return False

        # Delete any existing messages and load contacts in parallel
        logger.info("Loading contacts")
        await self.get_sim_contacts()

        # Configure SMS mode with a fast fallback
        logger.info("Configuring SMS mode")
        pdu_response = await self._send_at_command("AT+CMGF=0")
        if pdu_response.success:
            await self._send_at_command("AT+CSDH=1")  # Enable detailed SMS headers
            self._sms_reader = self.read_sms_pdu
            logger.info("Using PDU mode for SMS reception")
        else:
            # Fall back to text mode immediately without delay
            text_response = await self._send_at_command("AT+CMGF=1")
            if not text_response.success:
                logger.error("Failed to set any SMS mode")
                return False
            self._sms_reader = self.read_sms_text
            logger.info("Using text mode for SMS reception")

        logger.info("Modem setup completed successfully")
        return True

    @logfire.instrument("Send SMS notification {sms.sender}")
    async def _notify_single_message(self, sms: SMSMessage) -> bool:
        """Notify about a single message.

        :param sms: The SMS message to notify about
        :return: True if notification was sent, False otherwise
        """
        if not self.on_sms_received:
            logger.warning("No callback function set for SMS notification")
            return False

        # Handle both sync and async callbacks
        callback_result = self.on_sms_received(sms)
        if asyncio.iscoroutine(callback_result):
            await callback_result
        logger.info(f"Sent notification for SMS from {sms.sender}")

        # Clean up expired messages
        await self._cleanup_pending_messages()
        return True

    async def _cleanup_pending_messages(self) -> None:
        """Clean up old pending messages that are beyond the merge timeout."""
        if not self._merge_enabled:
            return

        with logfire.span("Cleanup Pending Messages"):
            now = now_utc()
            # Only clean up at the interval defined by merge_timeout
            if (now - self._last_cleanup).total_seconds() < self._merge_timeout:
                return

            self._last_cleanup = now
            logger.debug("Running pending message cleanup")
            expired_senders = []

            for sender, pending in self._pending_messages.items():
                # Ensure timestamp has timezone
                timestamp = pending.timestamp
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=datetime.UTC)

                time_diff = (now - timestamp).total_seconds()

                # Check if this message has expired
                if time_diff > self._merge_timeout:
                    logger.debug(f"Message from {sender} expired after {time_diff:.1f}s")

                    # Bug fix: Check for complete multipart messages before discarding
                    if pending.is_complete:
                        # Sort and merge one final time before notification
                        pending.merge_message()

                    # Notify if not already notified
                    if not pending.notified:
                        logger.debug("Notifying about expired/complete pending message")
                        await self._notify_single_message(pending.message)
                        pending.notified = True

                    # Always expire the message after timeout
                    expired_senders.append(sender)

                    if pending.is_complete:
                        logger.info(f"Completed multipart message from {sender}")
                    else:
                        logger.warning(f"Incomplete multipart message from {sender} expired after {time_diff:.1f}s")

            # Remove expired messages
            for sender in expired_senders:
                del self._pending_messages[sender]

            if expired_senders:
                logger.info(f"Cleaned up {len(expired_senders)} expired pending messages")

    async def _process_message__notify(self, pending: PendingMessage, key: str) -> None:
        """Notify about a message if needed.

        :param pending: The pending message information
        :param key: The key for the pending message
        """
        should_notify = pending.is_complete and not pending.notified

        # Send notification if needed
        if should_notify:
            await self._notify_single_message(pending.message)
            pending.notified = True

            # Remove from pending if complete
            if pending.is_complete:
                logger.debug(f"UDH message {key} complete, cleaning up")
                del self._pending_messages[key]

    async def _process_udh_message(self, sms: SMSMessage) -> bool:
        """Process a UDH message and handle merging if needed.

        :param sms: The SMS message to process
        :return: True if the message was processed, False otherwise (e.g., not a UDH message)
        """
        udh_info = sms.udh_info
        key = f"{sms.sender}_{udh_info.ref_num}"

        # Initialize a new pending message if needed
        if key not in self._pending_messages:
            self._pending_messages[key] = pending = PendingMessage(
                message=sms,
                parts=[sms],
                notified=False,
                expected_parts=udh_info.total_parts,
            )

        else:
            # Update existing pending message
            pending = self._pending_messages[key]
            pending.parts.append(sms)
            pending.timestamp = now_utc()  # Update timestamp for timeout purposes

            # Merge the parts
            pending.merge_message()

        # Determine if we should notify about this message
        await self._process_message__notify(pending, key)
        return True

    @logfire.instrument("Process SMS Message {sms.sender}")
    async def _process_message(self, sms: SMSMessage) -> None:
        """Process a received SMS message and handle multipart messages.

        :param sms: The SMS message to process
        """
        logger.debug(f"Processing SMS from {sms.sender}")

        # Skip merging if disabled
        if not self._merge_enabled:
            await self._notify_single_message(sms)
            return

        # Check for UDH information (only process multipart if UDH is present)
        if sms.udh_info:
            key = f"{sms.sender}_{sms.udh_info.ref_num}"

            # Initialize a new pending message if needed
            if key not in self._pending_messages:
                self._pending_messages[key] = pending = PendingMessage(
                    message=sms,
                    parts=[sms],
                    notified=False,
                    expected_parts=sms.udh_info.total_parts,
                )
            else:
                # Update existing pending message
                pending = self._pending_messages[key]
                pending.parts.append(sms)
                pending.timestamp = now_utc()  # Update timestamp for timeout purposes

                # Merge the parts
                pending.merge_message()

            # Determine if we should notify about this message
            if pending.is_complete and not pending.notified:
                await self._notify_single_message(pending.message)
                pending.notified = True

                # Remove from pending if complete
                if pending.is_complete:
                    logger.debug(f"UDH message {key} complete, cleaning up")
                    del self._pending_messages[key]
        else:
            # Not a multipart message, then notify
            await self._notify_single_message(sms)

        # Clean up expired messages
        await self._cleanup_pending_messages()

    @logfire.instrument("Read SMS: PDU Mode")
    async def read_sms_pdu(self) -> list[SMSMessage]:
        """Read all stored SMS messages in PDU mode and delete them after reading."""
        logger.debug("Reading SMS messages in PDU mode")
        messages: list[SMSMessage] = []

        try:
            response = await self._send_at_command("AT+CMGL=4")  # "ALL" messages
            if not response.success:
                logger.error("Failed to list SMS messages in PDU mode")
                return messages

            lines = response.raw_response.split("\n")
            i = 0
            while i < len(lines):
                line: str = lines[i].strip()
                if not line.startswith("+CMGL:"):
                    i += 1
                    continue

                try:
                    sms_index = line.split(",")[0].split(":")[1].strip()
                    pdu_data = lines[i + 1].strip()

                    if not pdu_data:
                        i += 2
                        continue

                    sms_info = decode_pdu(sms_index, pdu_data)
                    if sms_info:
                        messages.append(sms_info)
                        await self._process_message(sms_info)

                        # Delete the message after processing
                        await self._send_at_command(f"AT+CMGD={sms_index}")
                except Exception as e:
                    logger.error(f"Error processing PDU message: {e}", exc_info=e)

                i += 2

        except Exception as e:
            logger.error(f"Error reading PDU messages: {e}", exc_info=e)

        return messages

    @logfire.instrument("Read SMS: Text Mode")
    async def read_sms_text(self) -> list[SMSMessage]:
        """Read all stored SMS messages in text mode and delete them after reading."""
        logger.debug("Reading SMS messages in text mode")
        messages: list[SMSMessage] = []

        try:
            response = await self._send_at_command('AT+CMGL="ALL"')
            if not response.success or "+CMGL:" not in response.raw_response:
                return messages

            # Parse and process each message
            for entry in parse_text_mode_response(response.raw_response):
                try:
                    header = entry["header"]
                    text = entry["text"]
                    header_match = SMS_HEADER_REGEX.match(header)

                    if not header_match:
                        continue

                    sms_index = header_match.group("id")
                    sender = header_match.group("sender")
                    timestamp_str = header_match.group("timestamp")

                    # Process text and timestamp
                    decoded_text = decode_ucs2_text(text)
                    timestamp = parse_sms_timestamp(timestamp_str)
                    is_alphanumeric = sender and any(c.isalpha() for c in sender)

                    # Create and process a message
                    sms_message = SMSMessage(
                        index=sms_index,
                        sender=sender or "Unknown",
                        text=decoded_text,
                        timestamp=timestamp,
                        is_alphanumeric=bool(is_alphanumeric),
                    )

                    messages.append(sms_message)
                    await self._process_message(sms_message)

                    # Delete the message after processing
                    await self._send_at_command(f"AT+CMGD={sms_index}")
                except Exception as e:
                    logger.error(f"Error processing text mode entry: {e}", exc_info=e)

        except Exception as e:
            logger.error(f"Error reading text mode messages: {e}", exc_info=e)

        return messages

    @logfire.instrument("Get SIM Contacts")
    async def get_sim_contacts(self) -> dict[str, str]:
        """Fetch all contacts stored on the SIM card."""
        await self._send_at_command('AT+CPBS="SM"')
        response = await self._send_at_command("AT+CPBR=?")
        range_match = SIM_RANGE_REGEX.search(response.raw_response)

        if not range_match:
            return {}

        start_index, end_index = int(range_match.group(1)), int(range_match.group(2))
        response = await self._send_at_command(f"AT+CPBR={start_index},{end_index}")
        contacts = {}

        for line in response.raw_response.split("\n"):
            contact_match = CONTACT_REGEX.match(line.strip())
            if contact_match:
                contacts[contact_match.group("number")] = contact_match.group("name")

        self.contacts.update(contacts)
        return contacts

    async def run_sms_monitoring(
        self,
        callback: Callable[[SMSMessage], Any] | None = None,
        interval: float | None = None,
        lock: asyncio.Lock | None = None,
    ) -> None:
        """Start monitoring for new SMS messages.

        :param callback: Function to call when a new SMS is received
        :param interval: Check interval in seconds (defaults to instance setting)
        :param lock: Optional lock to use for concurrent access
        """
        if callback:
            self.on_sms_received = callback
        if not lock:
            lock = asyncio.Lock()
        if not interval:
            interval = self._check_interval

        # Use an adaptive interval strategy
        # For inactive periods, the interval will gradually increase up to this maximum
        max_inactive_interval = min(interval * 2, 5.0)  # Cap at 2x seconds max

        # After receiving messages, use this shorter interval for a while
        # to ensure we quickly catch all related messages (like multipart SMS)
        active_interval = max(0.5, interval / 2)  # Minimum 0.5s

        # Current interval starts at base value
        current_interval = interval

        # Track message activity to adjust polling frequency
        last_message_time = now_utc()
        message_activity = False

        logger.info(f"Starting SMS monitoring with base interval of {interval:.1f}s")
        logger.info(f"Using active interval: {active_interval:.1f}s, max interval: {max_inactive_interval:.1f}s")

        while True:
            check_start = now_utc()

            # Check for new messages
            async with lock:
                if not self.status:
                    logger.warning("Modem not yet set up before monitoring! Running setup...")
                    ok = await self.setup()
                    if not ok:
                        logger.error(f"Failed to set up modem before monitoring! Retrying after {interval:.2f}s...")
                        await asyncio.sleep(interval)
                        continue
                    logger.info("Modem setup completed successfully!")

                messages = await self._sms_reader()

            # Adjust polling interval based on activity
            if messages:
                # We received messages, so use the shorter active interval
                # for better responsiveness
                message_activity = True
                last_message_time = now_utc()
                current_interval = active_interval

                # Log activity
                logger.info(f"Processed {len(messages)} new messages")

            else:
                # No messages received, check if we should increase an interval
                inactive_time = (now_utc() - last_message_time).total_seconds()

                # If we've been in active mode but no messages for a while,
                # gradually return to normal polling
                if message_activity and inactive_time > ACTIVE_MODE_TIMEOUT:
                    message_activity = False
                    current_interval = interval
                    logger.debug("Returning to base polling interval")
                # If we continue to see no activity for a while, gradually increase an interval
                elif not message_activity and inactive_time > INACTIVE_MODE_THRESHOLD:
                    # Gradually increase an interval up to max_inactive_interval
                    current_interval = min(current_interval * 1.2, max_inactive_interval)
                    logger.debug(f"Adjusting polling interval to {current_interval:.1f}s")

            # Calculate actual sleep time (accounting for processing time)
            elapsed = (now_utc() - check_start).total_seconds()

            # Ensure we don't sleep for a negative amount of time
            sleep_time = max(MIN_SLEEP_INTERVAL, current_interval - elapsed)

            # Log unusual processing times
            if elapsed > SIGNIFICANT_PROCESSING_TIME:
                logger.debug(f"SMS check took {elapsed:.2f}s, sleeping {sleep_time:.2f}s")

            await asyncio.sleep(sleep_time)

    @logfire.instrument("Delete All SMS")
    async def delete_all_sms(self) -> bool:
        """Delete all SMS messages from the modem."""
        response = await self._send_at_command("AT+CMGD=1,4")
        return response.success

    async def _read_until_prompt(self, wait_time: float) -> tuple[bool, str]:
        """Read modem output until the prompt character '>' is found or timeout occurs.

        :param wait_time: Maximum time to wait for prompt
        :return: Tuple of (prompt_received, response_text)
        """
        start_time = now_utc()
        response = ""

        # Simple approach - just read until we find '>' or timeout
        deadline = start_time + datetime.timedelta(seconds=wait_time)

        try:
            while now_utc() < deadline:
                # Simple fixed timeout read
                chunk = await asyncio.wait_for(self._reader.read(BUFFER_SIZE), 0.5)
                if chunk:
                    response += chunk.decode(errors="ignore")
                    if ">" in response:
                        elapsed = (now_utc() - start_time).total_seconds()
                        logger.debug(f"SMS prompt received in {elapsed:.2f}s")
                        return True, response

                # Small sleep between reads if no prompt found
                await asyncio.sleep(0.1)

        except TimeoutError:
            # Timeout occurred during read
            pass

        return False, response

    async def _read_until_response(self, wait_time: float) -> str:
        """Read modem output until response completion or timeout.

        :param wait_time: Maximum time to wait for response.
        :return: Response text.
        """
        start_time = now_utc()
        response = ""
        deadline = start_time + datetime.timedelta(seconds=wait_time)

        try:
            while now_utc() < deadline:
                # Use a fixed timeout for each read attempt
                chunk = await asyncio.wait_for(self._reader.read(BUFFER_SIZE), 0.5)
                if chunk:
                    response += chunk.decode(errors="ignore")

                    # Check for success indicators
                    if "OK" in response or "+CMGS:" in response:
                        elapsed = (now_utc() - start_time).total_seconds()
                        logger.debug(f"Response completed in {elapsed:.2f}s")
                        break

                # Small sleep between reads
                await asyncio.sleep(0.1)

        except TimeoutError:
            # Timeout occurred during read
            pass

        return response.strip()

    async def _send_sms_message(self, cmd: str, message: str) -> str:
        """Send SMS message content after AT command.

        :param cmd: The AT command to send
        :param message: The message content to send
        :return: The modem response
        """
        try:
            # Clear the input buffer first
            await self._clear_input_buffer(MIN_SIGNIFICANT_DELAY)

            # Send the command (AT+CMGS="number" or similar)
            logger.debug(f"Sending SMS command: {cmd}")
            self._writer.write((cmd + "\r").encode())
            await self._writer.drain()

            # Wait for prompt character '>'
            prompt_received, response = await self._read_until_prompt(wait_time=SMS_PROMPT_TIMEOUT)

            if not prompt_received:
                logger.warning("SMS prompt not received, sending message anyway")

            # Send the message content followed by Ctrl+Z
            logger.debug(f"Sending SMS content: {message[:SMS_PREVIEW_LENGTH]}...")
            self._writer.write((message + chr(26)).encode())  # chr(26) is Ctrl+Z
            await self._writer.drain()

            # Wait for the response with timeout
            response = await self._read_until_response(wait_time=SMS_SEND_TIMEOUT)

            if response:
                logger.debug(f"SMS send response: {response[:SMS_RESPONSE_PREVIEW]}...")
            return response

        except Exception as e:
            logger.error(f"Error in _send_sms_message: {e}", exc_info=e)
            return ""

    @logfire.instrument("Send SMS {phone_number}: Text Mode")
    async def send_sms_text(self, phone_number: str, message: str) -> bool:
        """Send an SMS message in text mode."""
        # Switch to text mode
        await self._send_at_command("AT+CMGF=1")
        cmd = f'AT+CMGS="{phone_number}"'

        try:
            response = await self._send_sms_message(cmd, message)
            return "OK" in response or "+CMGS:" in response
        except Exception as e:
            logger.error(f"Error sending SMS: {e}", exc_info=e)
            return False

    @logfire.instrument("Send SMS {phone_number}: PDU Mode")
    async def send_sms_pdu(self, phone_number: str, message: str) -> bool:
        """Send SMS message in PDU mode."""
        try:
            # Switch to PDU mode
            await self._send_at_command("AT+CMGF=0")

            # Create the PDU
            pdu = messaging.sms.SmsSubmit(phone_number, message)
            pdu_data = pdu.to_pdu()[0]
            pdu_str = pdu_data.pdu

            # Calculate TPDU length
            smsc_len = int(pdu_str[0:2], 16)
            tpdu_len = (len(pdu_str) - 2 - (smsc_len * 2)) // 2

            # Send PDU command and data
            cmd = f"AT+CMGS={tpdu_len}"
            response = await self._send_sms_message(cmd, pdu_str)

            return "OK" in response or "+CMGS:" in response
        except Exception as e:
            logger.error(f"Error sending SMS in PDU mode: {e}", exc_info=e)
            return False

    @logfire.instrument("Send SMS {phone_number}")
    async def send_sms(self, phone_number: str, message: str) -> bool:
        """Send an SMS message using the best available method."""
        logger.info(f"Sending SMS to {phone_number}")

        # Try text mode first
        try:
            if await self.send_sms_text(phone_number, message):
                return True
        except Exception as e:
            logger.debug("Text mode failed, trying PDU mode", exc_info=e)

        # Fall back to PDU mode
        return await self.send_sms_pdu(phone_number, message)

    @logfire.instrument("Send Long SMS {phone_number}")
    async def send_long_sms(self, phone_number: str, message: str) -> bool:
        """Send a long SMS message by splitting it into multiple parts if needed.

        :param phone_number: Recipient phone number (international format with + preferred)
        :param message: Message text to send (can be longer than standard SMS length)
        :return: True if all message parts were sent successfully, False otherwise
        """
        # Bug fix: proper Unicode detection
        is_unicode = any(ord(c) > UNICODE_CHAR_THRESHOLD for c in message)
        max_length = UNICODE_SMS_LENGTH if is_unicode else ASCII_SMS_LENGTH

        if len(message) <= max_length:
            return await self.send_sms(phone_number, message)

        # Split the message into parts
        parts = []
        for i in range(0, len(message), max_length):
            parts.append(message[i : i + max_length])

        logger.info(f"Splitting message into {len(parts)} parts (unicode={is_unicode})")

        # Bug fix: Use a proper retry mechanism for failed parts
        success = True
        max_retries = 2

        for i, part in enumerate(parts, 1):
            part_text = f"({i}/{len(parts)}) {part}"
            sent = False

            # Try to send it with retries
            for attempt in range(max_retries):
                if await self.send_sms(phone_number, part_text):
                    sent = True
                    break
                logger.warning(f"Failed to send part {i}, attempt {attempt + 1}/{max_retries}")
                await asyncio.sleep(1)  # Shorter wait before retry

            if not sent:
                logger.error(f"Failed to send part {i} of {len(parts)} after {max_retries} attempts")
                success = False

        return success
