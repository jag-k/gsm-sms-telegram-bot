import logging

import logfire

from sms_reader.consts import SMS_HEADER_REGEX
from sms_reader.message_queue import MessageQueue
from sms_reader.models import SMSMessage
from sms_reader.transport import ModemTransport
from sms_reader.utils import (
    decode_pdu,
    decode_ucs2_text,
    parse_sms_timestamp,
    parse_text_mode_response,
)


logger = logging.getLogger(__name__)


class SMSReader:
    """Reads SMS messages from the modem in PDU or text mode."""

    def __init__(
        self,
        transport: ModemTransport,
        queue: MessageQueue,
        use_ucs2: bool = False,
    ) -> None:
        """Initialise the reader.

        :param transport: Underlying serial transport
        :param queue: Message queue to push parsed messages into
        :param use_ucs2: Whether text-mode responses are UCS2-encoded
        """
        self._transport = transport
        self._queue = queue
        self.use_ucs2 = use_ucs2

    @logfire.instrument("Read SMS: PDU Mode", extract_args=False)
    async def read_sms_pdu(self) -> list[SMSMessage]:
        """Read all stored SMS messages in PDU mode and delete them after reading."""
        logger.debug("Reading SMS messages in PDU mode")
        messages: list[SMSMessage] = []

        try:
            response = await self._transport.send_at_command("AT+CMGL=4")
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
                    sms_index = line.split(",", maxsplit=1)[0].split(":", maxsplit=1)[1].strip()
                    pdu_data = lines[i + 1].strip()

                    if not pdu_data:
                        i += 2
                        continue

                    sms_info = decode_pdu(sms_index, pdu_data)
                    if sms_info:
                        messages.append(sms_info)
                        await self._queue.process_message(sms_info)
                        await self._transport.send_at_command(f"AT+CMGD={sms_index}")
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
            response = await self._transport.send_at_command('AT+CMGL="ALL"')
            if not response.success or "+CMGL:" not in response.raw_response:
                return messages

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

                    if self.use_ucs2:
                        text = decode_ucs2_text(text)
                    timestamp = parse_sms_timestamp(timestamp_str)
                    is_alphanumeric = sender and any(c.isalpha() for c in sender)

                    sms_message = SMSMessage(
                        index=sms_index,
                        sender=sender or "Unknown",
                        text=text,
                        timestamp=timestamp,
                        is_alphanumeric=bool(is_alphanumeric),
                    )

                    messages.append(sms_message)
                    await self._queue.process_message(sms_message)
                    await self._transport.send_at_command(f"AT+CMGD={sms_index}")
                except Exception as e:
                    logger.error(f"Error processing text mode entry: {e}", exc_info=e)

        except Exception as e:
            logger.error(f"Error reading text mode messages: {e}", exc_info=e)

        return messages
