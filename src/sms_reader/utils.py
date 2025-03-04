import datetime
import logging
import string

import messaging.sms

from sms_reader.models import PendingMessage, SMSMessage


logger = logging.getLogger(__name__)


def parse_text_mode_response(response_text: str) -> list[dict]:
    """Parse the AT+CMGL response into a list of SMS entries.

    :param response_text: Raw response from AT+CMGL command
    :return: List of dictionaries with header and text fields
    """
    sms_entries = []
    current_entry = None

    for line in map(str.strip, response_text.split("\n")):
        # If the line starts with +CMGL, it is an SMS header
        if line.startswith("+CMGL:"):
            # If we already have a current entry, add it to the list
            if current_entry:
                sms_entries.append(current_entry)

            # Create a new entry
            current_entry = {"header": line, "text": ""}
        elif current_entry:
            # If we have a current entry, add text to it
            if current_entry["text"]:
                current_entry["text"] += "\n"
            current_entry["text"] += line

    # Add the last entry
    if current_entry:
        sms_entries.append(current_entry)

    return sms_entries


def decode_ucs2_text(text: str) -> str:
    """Decode UCS2 (hexadecimal) text to Unicode string.

    :param text: Hexadecimal string to decode
    :return: Decoded text or original text if not in UCS2 format
    """
    if all(c in string.hexdigits for c in text) and len(text) % 4 == 0:
        try:
            return bytearray.fromhex(text).decode("utf-16-be")
        except Exception as e:
            logger.error(f"Failed to decode UCS2 text: {e}", exc_info=e)

    return text


def parse_sms_timestamp(timestamp: str | datetime.datetime | None) -> datetime.datetime:
    """Parse SMS timestamp to a datetime object.

    :param timestamp: Timestamp as a string or datetime object
    :return: Parsed datetime with timezone information
    """
    # If it is already a datetime object, return it
    if isinstance(timestamp, datetime.datetime):
        return timestamp

    # If it is None, return the current time
    if not timestamp:
        return datetime.datetime.now()

    try:
        # Handle string timestamp
        # SMS timestamp format: "YY/MM/DD,HH:MM:SS±ZZ"

        # Handle timezone part separately as it is not standard
        if "+" in timestamp:
            dt_str, tz_str = timestamp.rsplit("+", 1)
            tz_sign = 1
        elif "-" in timestamp:
            dt_str, tz_str = timestamp.rsplit("-", 1)
            tz_sign = -1
        else:
            dt_str = timestamp
            tz_sign = 0
            tz_str = "00"

        # Parse the datetime part
        dt = datetime.datetime.strptime(dt_str, "%y/%m/%d,%H:%M:%S")

        # Add timezone if present
        if tz_sign != 0:
            # Convert quarter-hours to hours (e.g., 04 = 1 hour)
            tz_hours = int(tz_str) // 4
            tz = datetime.timezone(datetime.timedelta(hours=tz_sign * tz_hours))
            dt = dt.replace(tzinfo=tz)
        else:
            dt = dt.replace(tzinfo=datetime.UTC)

        return dt
    except Exception as e:
        logger.error(f"Error parsing timestamp '{timestamp}': {e}", exc_info=e)
        return datetime.datetime.now()


def decode_pdu(sms_index: str, pdu_data: str) -> SMSMessage | None:
    """Decode PDU data of an SMS and return structured information.

    :param sms_index: Index of the SMS in storage
    :param pdu_data: Raw PDU data string
    :return: Structured SMS message data or None if decoding fails
    """
    try:
        # Decode PDU data
        sms = messaging.sms.SmsDeliver(pdu_data)

        # Get sender information
        sender = sms.number

        # Get message text
        text = sms.text

        # Parse timestamp to datetime
        timestamp = parse_sms_timestamp(sms.date)

        # Check if this is an alphanumeric sender ID
        is_alphanumeric = False
        clean_sender = sender or "Unknown"
        sender_type = None

        if sender and any(c.isalpha() for c in sender):
            is_alphanumeric = True
            # If the sender contains non-alphanumeric characters, clean it
            if any(not c.isalnum() for c in sender):
                clean_sender = "".join(c for c in sender if c.isalnum())

        # Extract additional information from the PDU data directly
        try:
            # Skip service center info (first byte is length)
            sc_len = int(pdu_data[0:2], 16)
            offset = 2 + sc_len * 2

            # PDU type is the next byte (useful for determining a message type)
            int(pdu_data[offset : offset + 2], 16)
            offset += 2

            # Sender address length is the next byte (useful for validation)
            int(pdu_data[offset : offset + 2], 16)
            offset += 2

            # Sender address type is the next byte
            sender_type = int(pdu_data[offset : offset + 2], 16)

            # Check if this is an alphanumeric address (type 0xD0 or 0x50)
            if (sender_type & 0x70) == 0x50:  # noqa: PLR2004
                is_alphanumeric = True
        except Exception as e:
            logger.debug(f"Error parsing PDU structure: {e}")

        # Return structured SMS information
        return SMSMessage(
            index=sms_index,
            sender=sender or "Unknown",
            clean_sender=clean_sender,
            text=text,
            timestamp=timestamp,
            is_alphanumeric=is_alphanumeric,
            sender_type=sender_type,
        )

    except Exception as e:
        logger.error(f"Failed to decode PDU data: {e}", exc_info=e)
        return None


def sort_message_parts(pending: PendingMessage) -> None:
    """Sort message parts by their order numbers."""
    try:
        pending["parts"].sort(key=lambda m: int(m.text.split(")")[0].split("/")[0].strip("(")))
    except (ValueError, IndexError):
        logger.warning("Failed to sort message parts, using original order")


def create_merged_message(pending: PendingMessage) -> SMSMessage:
    """Create a merged message from all parts."""
    merged_text = "".join(part.text for part in pending["parts"])
    original_message = pending["message"]

    return SMSMessage(
        index=f"{original_message.index}_merged_{len(pending['parts'])}",
        sender=original_message.sender,
        clean_sender=original_message.clean_sender,
        text=merged_text,
        timestamp=original_message.timestamp,
        is_alphanumeric=original_message.is_alphanumeric,
        sender_type=original_message.sender_type,
    )


def check_if_last_part(pending: PendingMessage) -> bool:
    """Check if we've received the last part of the message."""
    try:
        for part in pending["parts"]:
            if "(" in part.text and "/" in part.text and ")" in part.text:
                current, total = map(int, part.text.split(")")[0].strip("(").split("/"))
                if current == total and len(pending["parts"]) >= total:
                    return True
    except (ValueError, IndexError):
        logger.debug("Failed to parse message part numbers")
    return False


def extract_part_info(text: str) -> tuple[int, int] | None:
    """Extract part number and total parts from the message text.
    Returns (current_part, total_parts) or None if not found."""
    try:
        if "(" in text and "/" in text and ")" in text:
            part_str = text.split(")")[0].strip("(")
            current, total = map(int, part_str.split("/"))
            return current, total
    except (ValueError, IndexError):
        pass
    return None
