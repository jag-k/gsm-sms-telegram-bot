import asyncio
import datetime
import logging
import re
import string

from asyncio import StreamReader, StreamWriter
from collections.abc import Awaitable, Callable
from typing import Any

import messaging.sms
import serial_asyncio

from sms_reader.consts import ASCII_SMS_LENGTH, CONTACT_REGEX, SIM_RANGE_REGEX, SMS_HEADER_REGEX
from sms_reader.models import ATResponse, ModemStatus, PendingMessage, SMSMessage
from sms_reader.utils import (
    check_if_last_part,
    create_merged_message,
    decode_pdu,
    decode_ucs2_text,
    parse_sms_timestamp,
    parse_text_mode_response,
    sort_message_parts,
)


logger = logging.getLogger(__name__)


class GSMModem:
    """GSM Modem interface for handling SMS messages with proper sender ID handling.

    This class provides methods to connect to a GSM modem, read SMS messages in
    both PDU and text modes, and properly decode alphanumeric sender IDs.
    """

    def __init__(self, port: str = "/dev/ttyUSB0", baud_rate: int = 115200, merge_messages_timeout: int = 10):
        """Initialize the GSM modem connection parameters.

        :param port: Serial port where the modem is connected
        :param baud_rate: Baud rate for serial communication
        :param merge_messages_timeout: Timeout in seconds for merging messages. Set to 0 to disable merging.
        """
        self.port = port
        self.baud_rate = baud_rate
        self._reader: StreamReader
        self._writer: StreamWriter
        self._sms_reader: Callable[[], Awaitable[list[SMSMessage]]] | None = None
        self.on_sms_received: Callable[[SMSMessage], Any] | None = None
        self.contacts: dict[str, str] = {}

        self._pending_messages: dict[str, PendingMessage] = {}  # Dictionary to store pending messages for merging
        self._merge_timeout = merge_messages_timeout  # Seconds to wait for merging messages
        self._last_cleanup = datetime.datetime.now(datetime.UTC)
        self._merge_enabled = merge_messages_timeout > 0  # Flag to enable/disable merging

    def _can_merge_message(self, sms: SMSMessage) -> bool:
        """Check if the message can be merged."""
        return self._merge_enabled and not sms.is_alphanumeric and sms.sender in self._pending_messages

    def _is_within_timeout(self, pending: PendingMessage) -> bool:
        """Check if the pending message is within the merge timeout."""
        now = datetime.datetime.now(datetime.UTC)
        timestamp = pending["timestamp"]
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=datetime.UTC)

        time_diff = (now - timestamp).total_seconds()

        if time_diff > self._merge_timeout:
            logger.debug(f"Message too old to merge (diff: {time_diff}s > timeout: {self._merge_timeout}s)")
            return False
        return True

    async def _notify_if_needed(self, pending: PendingMessage, is_last_part: bool) -> None:
        """Notify callback if needed and handle cleanup."""
        if not pending.get("notified", False) or is_last_part:
            if self.on_sms_received:
                logger.debug("Notifying callback about merged message")
                callback_result = self.on_sms_received(pending["message"])
                if asyncio.iscoroutine(callback_result):
                    await callback_result
                pending["notified"] = True

                if is_last_part:
                    logger.debug("Last part received, cleaning up pending message")
                    del self._pending_messages[pending["message"].sender]

    async def _try_merge_message(self, sms: SMSMessage) -> bool:
        """Try to merge an SMS with pending messages from the same sender.

        :param sms: The SMS message to process
        :return: True if the message was merged, False otherwise
        """
        if not self._can_merge_message(sms):
            return False

        pending = self._pending_messages[sms.sender]
        if not self._is_within_timeout(pending):
            return False

        # Add new part and update timestamp
        pending["parts"].append(sms)
        pending["timestamp"] = datetime.datetime.now(datetime.UTC)

        sort_message_parts(pending)
        merged_sms = create_merged_message(pending)
        pending["message"] = merged_sms

        is_last_part = check_if_last_part(pending)
        await self._notify_if_needed(pending, is_last_part)

        return True

    async def _cleanup_pending_messages(self) -> None:
        """Clean up old pending messages that are beyond the merge timeout."""
        # Skip if merging is disabled
        if not self._merge_enabled:
            return

        now = datetime.datetime.now(datetime.UTC)

        # Only clean up every merge_timeout/2 seconds to balance between
        # responsiveness and performance
        if (now - self._last_cleanup).total_seconds() < (self._merge_timeout / 2):
            return

        self._last_cleanup = now
        logger.debug("Cleaning up pending messages")

        # Find expired messages
        expired_senders = []
        for sender, pending in self._pending_messages.items():
            timestamp = pending["timestamp"]
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=datetime.UTC)
            time_diff = (now - timestamp).total_seconds()

            if time_diff > self._merge_timeout:
                logger.debug(f"Message from {sender} expired after {time_diff}s")
                expired_senders.append(sender)

                # If we haven't notified about this message yet, do it now
                if not pending.get("notified", False) and self.on_sms_received:
                    logger.debug("Notifying about expired pending message")
                    callback_result = self.on_sms_received(pending["message"])
                    if asyncio.iscoroutine(callback_result):
                        await callback_result

        # Remove expired messages
        for sender in expired_senders:
            del self._pending_messages[sender]

        if expired_senders:
            logger.info(f"Cleaned up {len(expired_senders)} expired pending messages")

    async def _process_and_notify(self, sms: SMSMessage) -> None:
        """Process a received SMS message and notify the callback if needed.

        This method attempts to merge consecutive messages from the same sender
        before notifying the callback.

        :param sms: The received SMS message
        """
        logger.debug(f"Processing SMS from {sms.sender}")

        # Skip merging if disabled
        if not self._merge_enabled:
            logger.debug("Message merging disabled, sending directly to callback")
            if self.on_sms_received:
                callback_result = self.on_sms_received(sms)
                if asyncio.iscoroutine(callback_result):
                    await callback_result
            return

        # Try to merge with pending messages
        logger.debug("Attempting to merge message")
        merged = await self._try_merge_message(sms)

        # If not merged and not alphanumeric, store as a potential first part
        if not merged and not sms.is_alphanumeric:
            logger.debug(f"Message not merged, storing as potential first part from {sms.sender}")
            # Clean up old pending messages first
            await self._cleanup_pending_messages()

            # Store as a potential first part of a multipart message
            self._pending_messages[sms.sender] = {
                "message": sms,
                "timestamp": datetime.datetime.now(datetime.UTC),
                "parts": [sms],
                "notified": False,  # Track if we've notified about this message
            }

            # Only notify if it is likely a single message
            if len(sms.text) < ASCII_SMS_LENGTH:
                logger.debug("Message appears to be single part, notifying callback")
                if self.on_sms_received:
                    callback_result = self.on_sms_received(sms)
                    if asyncio.iscoroutine(callback_result):
                        await callback_result
                    self._pending_messages[sms.sender]["notified"] = True
        elif not merged:
            # For alphanumeric senders or when merging failed, notify immediately
            logger.debug("Sending a non-mergeable message directly to callback")
            if self.on_sms_received:
                callback_result = self.on_sms_received(sms)
                if asyncio.iscoroutine(callback_result):
                    await callback_result

    async def connect(self) -> bool:
        """Establish a connection with the modem.

        :return: True if the connection was successful, False otherwise
        """
        try:
            # noinspection PyAttributeOutsideInit
            self._reader, self._writer = await serial_asyncio.open_serial_connection(
                url=self.port,
                baudrate=self.baud_rate,
            )
            logger.info("Connected to GSM modem.")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to modem: {e}", exc_info=e)
            return False

    async def _send_at_command(self, command: str, delay: float = 0.5) -> ATResponse:
        """Send an AT command and return the structured response.

        :param command: AT command to send
        :param delay: Time to wait for response in seconds
        :return: Structured response containing success status and data
        """
        if self._writer is None:
            return ATResponse(raw_response="", error_message="Modem not connected")

        try:
            self._writer.write((command + "\r\n").encode())
            await asyncio.sleep(delay)
            response_bytes = await self._reader.read(1024)
            response = response_bytes.decode(errors="ignore").strip()

            # Check if the response indicates success
            if "OK" in response:
                return ATResponse(raw_response=response)
            elif "ERROR" in response:
                return ATResponse(
                    raw_response=response,
                    error_message=f"Command failed: {command}",
                )
            else:
                # Some commands might not return OK but still succeed
                return ATResponse(raw_response=response)

        except Exception as e:
            logger.error(f"Error sending AT command: {e}", exc_info=e)
            return ATResponse(raw_response="", error_message=str(e))

    async def check_modem_status(self) -> ModemStatus:
        """Check SIM card status, network registration, and signal strength.

        :return: Object with modem status information
        """
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
            # Parse registration status
            # +CREG: 0,1 means registered to home network
            # +CREG: 0,5 means registered to roaming network
            match = re.search(r"\+CREG: \d,(\d)", net_response.raw_response)
            if match and match.group(1) in ["1", "5"]:
                status.network_registered = True

        # Check signal strength
        signal_response = await self._send_at_command("AT+CSQ")
        if signal_response.success:
            # Parse signal strength
            # +CSQ: <rssi>,<ber> where rssi is 0-31, 99=unknown
            match = re.search(r"\+CSQ: (\d+),", signal_response.raw_response)
            if match:
                rssi = int(match.group(1))
                status.signal_strength = rssi

        return status

    async def setup(self) -> bool:
        """Configure the modem for SMS reception with proper sender ID handling.

        This method connects to the modem, checks its status, loads contacts,
        and configures it for optimal SMS reception with sender ID support.

        :return: True if setup was successful, False otherwise
        """
        # Connect to the modem
        if not await self.connect():
            logger.error("Failed to connect to modem")
            return False

        # Check modem status
        status = await self.check_modem_status()
        if not status.sim_ready:
            logger.error("SIM card not ready")
            return False

        if not status.network_registered:
            logger.error("Not registered to network")
            return False

        # Load contacts
        await self.get_sim_contacts()

        # Set UCS2 character set for proper text encoding
        charset_response = await self._send_at_command('AT+CSCS="UCS2"')
        if not charset_response.success:
            logger.warning("Failed to set UCS2 character set")

        # Enable PDU mode for better sender ID information
        pdu_response = await self._send_at_command("AT+CMGF=0")
        if pdu_response.success:
            # Enable detailed SMS header information
            header_response = await self._send_at_command("AT+CSDH=1")
            if not header_response.success:
                logger.warning("Failed to enable detailed SMS headers")

            self._sms_reader = self.read_sms_pdu
            logger.info("Using PDU mode for SMS reception")
        else:
            # Fall back to text mode
            text_response = await self._send_at_command("AT+CMGF=1")
            if not text_response.success:
                logger.error("Failed to set any SMS mode")
                return False

            self._sms_reader = self.read_sms_text
            logger.info("Using text mode for SMS reception")

        return True

    async def read_sms_pdu(self) -> list[SMSMessage]:
        """Read all stored SMS messages in PDU mode and delete them after reading.

        :return: List of decoded SMS messages
        """
        logger.debug("Reading SMS messages in PDU mode")
        messages: list[SMSMessage] = []

        try:
            # List all messages
            response = await self._send_at_command("AT+CMGL=4")  # "ALL" messages
            if not response.success:
                logger.error("Failed to list SMS messages in PDU mode")
                return messages

            lines = response.raw_response.split("\n")
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                if not line.startswith("+CMGL:"):
                    i += 1
                    continue

                try:
                    # Parse index and length
                    sms_index = line.split(",")[0].split(":")[1].strip()
                    logger.debug(f"Processing PDU message at index {sms_index}")

                    # Get PDU data from next line
                    pdu_data = lines[i + 1].strip()
                    if not pdu_data:
                        logger.warning(f"Empty PDU data for message {sms_index}")
                        i += 2
                        continue

                    # Decode PDU
                    sms_info = decode_pdu(sms_index, pdu_data)
                    if not sms_info:
                        logger.warning(f"Failed to decode PDU message {sms_index}")
                        i += 2
                        continue

                    logger.debug(f"Successfully decoded PDU message from {sms_info.sender}")
                    messages.append(sms_info)
                    await self._process_and_notify(sms_info)

                    # Delete the message after processing
                    logger.debug(f"Deleting processed message {sms_index}")
                    delete_response = await self._send_at_command(f"AT+CMGD={sms_index}")
                    if not delete_response.success:
                        logger.warning(f"Failed to delete SMS message {sms_index}")

                except Exception as e:
                    logger.error(f"Error processing PDU message: {e}", exc_info=e)

                i += 2

        except Exception as e:
            logger.error(f"Error reading PDU messages: {e}", exc_info=e)

        logger.info(f"Read {len(messages)} messages in PDU mode")
        return messages

    async def _process_text_mode_entry(self, entry: dict) -> SMSMessage | None:
        """Process a single SMS entry from text mode and delete it after processing.

        :param entry: Dictionary with header and text fields
        :return: Processed SMS message or None if processing failed
        """
        try:
            # Extract information from the header
            header = entry["header"]
            text = entry["text"]

            # Use the precompiled regex to extract all parameters
            header_match = SMS_HEADER_REGEX.match(header)

            if not header_match:
                logger.warning(f"Failed to parse SMS header: {header}")
                return None

            sms_index = header_match.group("id")
            sender = header_match.group("sender")
            timestamp_str = header_match.group("timestamp")

            logger.debug(f"Processing text mode message {sms_index} from {sender}")

            # If the text is in hexadecimal format (UCS2), decode it
            decoded_text = decode_ucs2_text(text)

            # Parse timestamp
            timestamp = parse_sms_timestamp(timestamp_str)

            # Check if this is an alphanumeric sender ID
            is_alphanumeric = sender and any(c.isalpha() for c in sender)
            clean_sender = sender or "Unknown"

            if is_alphanumeric and any(not c.isalnum() for c in clean_sender):
                clean_sender = "".join(c for c in clean_sender if c.isalnum())
                logger.debug(f"Cleaned alphanumeric sender ID: {clean_sender}")

            # Create SMS info structure
            sms_message = SMSMessage(
                index=sms_index,
                sender=sender or "Unknown",
                clean_sender=clean_sender,
                text=decoded_text,
                timestamp=timestamp,
                is_alphanumeric=bool(is_alphanumeric),
            )

            # Process and notify about the message
            await self._process_and_notify(sms_message)

            # Delete the message after processing
            logger.debug(f"Deleting processed message {sms_index}")
            delete_response = await self._send_at_command(f"AT+CMGD={sms_index}")
            if not delete_response.success:
                logger.warning(f"Failed to delete SMS message {sms_index}")

            return sms_message

        except Exception as e:
            logger.error(f"Error processing text mode entry: {e}", exc_info=e)
            return None

    async def read_sms_text(self) -> list[SMSMessage]:
        """Read all stored SMS messages in text mode and delete them after reading.

        :return: List of decoded SMS messages
        """
        logger.debug("Reading SMS messages in text mode")
        messages: list[SMSMessage] = []

        try:
            response = await self._send_at_command('AT+CMGL="ALL"')
            if not response.success:
                logger.error("Failed to list SMS messages in text mode")
                return messages

            if "+CMGL:" not in response.raw_response:
                logger.debug("No messages found in text mode")
                return messages

            # Parse the response into entries
            sms_entries = parse_text_mode_response(response.raw_response)
            logger.debug(f"Found {len(sms_entries)} messages in text mode")

            # Process each entry
            for entry in sms_entries:
                try:
                    sms_message = await self._process_text_mode_entry(entry)
                    if sms_message:
                        logger.debug(f"Successfully processed message from {sms_message.sender}")
                        messages.append(sms_message)
                except Exception as e:
                    logger.error(f"Error processing text mode entry: {e}", exc_info=e)

        except Exception as e:
            logger.error(f"Error reading text mode messages: {e}", exc_info=e)

        logger.info(f"Read {len(messages)} messages in text mode")
        return messages

    async def get_sim_contacts(self) -> dict[str, str]:
        """Fetch all contacts stored on the SIM card.

        :return: Dictionary mapping phone numbers to contact names
        """
        # Select SIM storage
        response = await self._send_at_command('AT+CPBS="SM"')
        if not response.success:
            logger.error("Failed to select SIM storage")
            return {}

        # Get available contact index range
        response = await self._send_at_command("AT+CPBR=?")
        range_match = SIM_RANGE_REGEX.search(response.raw_response)

        if not range_match:
            logger.error("Failed to determine SIM contact range")
            return {}

        start_index, end_index = int(range_match.group(1)), int(range_match.group(2))
        logger.info(f"Reading SIM contacts from index {start_index} to {end_index}")

        # Read all contacts
        response = await self._send_at_command(f"AT+CPBR={start_index},{end_index}")
        contacts = {}

        for line in response.raw_response.split("\n"):
            contact_match = CONTACT_REGEX.match(line.strip())
            if contact_match:
                contacts[contact_match.group("number")] = contact_match.group("name")

        logger.info(f"Loaded {len(contacts)} contacts from SIM")
        self.contacts.update(contacts)
        return contacts

    async def start_sms_monitoring(
        self,
        callback: Callable[[SMSMessage], Any] | None = None,
        interval: int = 10,
    ) -> None:
        """Start monitoring for new SMS messages.

        :param callback: Function to call when a new SMS is received. Can be async.
        :param interval: Check an interval in seconds
        """
        if callback:
            self.on_sms_received = callback

        while True:
            if self._sms_reader:
                await self._sms_reader()
            else:
                logger.error("SMS reader not configured")
                break

            await asyncio.sleep(interval)

    async def delete_all_sms(self) -> bool:
        """Delete all SMS messages from the modem.

        :return: True if deletion was successful, False otherwise
        """
        response = await self._send_at_command("AT+CMGD=1,4")
        if response.success:
            logger.info("All SMS messages deleted")
            return True
        else:
            logger.error(f"Failed to delete SMS messages: {response.error_message}")
            return False

    async def _send_sms_message(self, cmd: str, message: str) -> str:
        self._writer.write((cmd + "\r").encode())
        await asyncio.sleep(1.0)  # Wait for a prompt

        # Send the PDU data followed by Ctrl+Z
        self._writer.write((message + chr(26)).encode())

        # Wait for response
        await asyncio.sleep(5.0)
        response_bytes = await self._reader.read(1024)
        return response_bytes.decode(errors="ignore").strip()

    async def send_sms_text(self, phone_number: str, message: str) -> bool:
        """Send an SMS message in text mode.

        :param phone_number: Recipient phone number (international format with + preferred)
        :param message: Message text to send
        :return: True if a message was sent successfully, False otherwise
        """
        # Switch to text mode if needed
        mode_response = await self._send_at_command("AT+CMGF=1")
        if not mode_response.success:
            logger.error("Failed to switch to text mode for sending SMS")
            return False

        # Set the recipient phone number
        cmd = f'AT+CMGS="{phone_number}"'

        try:
            response = await self._send_sms_message(cmd, message)

            if "OK" in response or "+CMGS:" in response:
                logger.info(f"SMS sent to {phone_number}")
                return True
            else:
                logger.error(f"Failed to send SMS: {response}")
                return False
        except Exception as e:
            logger.error(f"Error sending SMS: {e}", exc_info=e)
            return False

    async def send_sms_pdu(self, phone_number: str, message: str) -> bool:
        """Send SMS a message in PDU mode.

        :param phone_number: Recipient phone number (international format with + preferred)
        :param message: Message text to send
        :return: True if a message was sent successfully, False otherwise
        """
        try:
            # Switch to PDU mode
            mode_response = await self._send_at_command("AT+CMGF=0")
            if not mode_response.success:
                logger.error("Failed to switch to PDU mode for sending SMS")
                return False

            # Create the PDU
            try:
                pdu = messaging.sms.SmsSubmit(phone_number, message)

                # Get the PDU string and length
                pdu_data = pdu.to_pdu()[0]
                pdu_str = pdu_data.pdu

                # Calculate the TPDU length (PDU length without SMSC part)
                # The first byte (2 hex chars) is the SMSC length
                smsc_len = int(pdu_str[0:2], 16)
                tpdu_len = (len(pdu_str) - 2 - (smsc_len * 2)) // 2

                # Send the PDU command with TPDU length
                cmd = f"AT+CMGS={tpdu_len}"

                logger.debug(f"Sending PDU command: {cmd}")
                logger.debug(f"PDU data: {pdu_str}")

                # Send command and wait for a prompt
                response = await self._send_sms_message(cmd, pdu_str)

                if "OK" in response or "+CMGS:" in response:
                    logger.info(f"SMS sent to {phone_number} in PDU mode")
                    return True
                else:
                    logger.error(f"Failed to send SMS in PDU mode: {response}")
                    return False
            except Exception as inner_e:
                logger.error(f"Error creating or sending PDU: {inner_e}", exc_info=inner_e)
                return False
        except Exception as e:
            logger.error(f"Error sending SMS in PDU mode: {e}", exc_info=e)
            return False

    async def send_sms(self, phone_number: str, message: str) -> bool:
        """Send an SMS message using the best available method.

        This method will try to send the message in text mode first for better reliability
        and fall back to PDU mode if text mode fails.

        :param phone_number: Recipient phone number (international format with + preferred)
        :param message: Message text to send
        :return: True if a message was sent successfully, False otherwise
        """
        logger.info(f"Sending SMS to {phone_number}")

        # Try text mode first (more reliable)
        try:
            logger.debug("Attempting to send SMS in text mode")
            if await self.send_sms_text(phone_number, message):
                logger.info("SMS sent successfully in text mode")
                return True
        except Exception as e:
            logger.warning(f"Failed to send SMS in text mode, falling back to PDU mode: {e}")

        # Fall back to PDU mode
        logger.debug("Attempting to send SMS in PDU mode")
        success = await self.send_sms_pdu(phone_number, message)
        if success:
            logger.info("SMS sent successfully in PDU mode")
        else:
            logger.error("Failed to send SMS in both text and PDU modes")
        return success

    async def send_long_sms(self, phone_number: str, message: str) -> bool:
        """Send a long SMS message by splitting it into multiple parts if needed.

        :param phone_number: Recipient phone number (international format with + preferred)
        :param message: Message text to send (can be longer than standard SMS length)
        :return: True if all message parts were sent successfully, False otherwise
        """
        # Check if the message needs to be split
        # For simplicity, we will use a conservative estimate:
        # - 160 chars for ASCII messages
        # - 70 chars for Unicode messages (like Russian)

        # Check if a message contains non-ASCII characters
        is_unicode = any(c in string.printable for c in message)
        max_length = 70 if is_unicode else 160

        if len(message) <= max_length:
            # Short message, send it as a single SMS
            return await self.send_sms(phone_number, message)

        # Split the message into parts
        parts = []
        for i in range(0, len(message), max_length):
            parts.append(message[i : i + max_length])

        logger.info(f"Splitting message into {len(parts)} parts")

        # Send each part
        success = True
        for i, part in enumerate(parts, 1):
            part_text = f"({i}/{len(parts)}) {part}"
            if not await self.send_sms(phone_number, part_text):
                logger.error(f"Failed to send part {i} of {len(parts)}")
                success = False

        return success
