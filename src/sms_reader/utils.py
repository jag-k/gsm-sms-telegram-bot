import datetime
import logging
import re
import string

import messaging.sms

from sms_reader.consts import (
    ASCII_SMS_LENGTH,
    UNICODE_CHAR_THRESHOLD,
    UNICODE_SMS_LENGTH,
)
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
        return datetime.datetime.now(datetime.UTC)

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
        return datetime.datetime.now(datetime.UTC)


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
        sender_type = None

        if sender and any(c.isalpha() for c in sender):
            is_alphanumeric = True

        # Extract UDH information for multipart messages
        udh_info = None
        if hasattr(sms, "udh") and sms.udh:
            for ie in sms.udh:
                # Check for concatenated SMS information element (0x00 or 0x08)
                if ie.iei in (0, 8):
                    udh_info = {
                        "ref_num": ie.data[0],  # Reference number
                        "total_parts": ie.data[1],  # Total number of parts
                        "current_part": ie.data[2],  # Current part number
                    }
                    break

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
            text=text,
            timestamp=timestamp,
            is_alphanumeric=is_alphanumeric,
            sender_type=sender_type,
            udh_info=udh_info,
        )

    except Exception as e:
        logger.error(f"Failed to decode PDU data: {e}", exc_info=e)
        return None


def extract_part_info(text: str) -> tuple[int, int] | None:
    """Extract part number and total parts from the message text.
    Returns (current_part, total_parts) or None if not found."""
    try:
        # Look for patterns like (1/3) at the beginning of the message
        match = re.match(r"^\s*\((\d+)/(\d+)\)", text)
        if match:
            current, total = map(int, match.groups())
            return current, total

        # Also try a more flexible pattern that might appear anywhere in the text
        match = re.search(r"\((\d+)/(\d+)\)", text)
        if match:
            current, total = map(int, match.groups())
            return current, total
    except (ValueError, IndexError, AttributeError):
        pass
    return None


def sort_message_parts(pending: PendingMessage) -> None:
    """Sort message parts by their order numbers using metadata."""
    try:
        # First, check if we have UDH information (most reliable)
        parts_with_udh: list[tuple[int, SMSMessage]] = [
            (part_num, part) for part in pending.parts if (part_num := (part.udh_info or {}).get("current_part", 0))
        ]

        # If all parts have UDH info, sort by UDH part number
        if all(part_num is not None for part_num, _ in parts_with_udh):
            parts_with_udh.sort(key=lambda x: x[0])
            pending.parts = [part for _, part in parts_with_udh]
            return

        # Next, try to sort by explicit part numbers in text
        parts_with_numbers: list[tuple[int, SMSMessage]] = []
        for part in pending.parts:
            part_info = extract_part_info(part.text)
            if part_info:
                current, _ = part_info
                parts_with_numbers.append((current, part))

        if parts_with_numbers and len(parts_with_numbers) == len(pending.parts):
            # Sort by part number
            parts_with_numbers.sort(key=lambda x: x[0])
            pending.parts = [part for _, part in parts_with_numbers]
            return

        # Fallback to the original method if no explicit part numbers
        # This is the least reliable method and should only be used as a last resort
        logger.warning("Using text-based part sorting as fallback - less reliable")
        try:
            pending.parts.sort(key=lambda m: int(m.text.split(")")[0].split("/")[0].strip("(")))
        except (ValueError, IndexError):
            logger.warning("Failed to sort by text pattern, using timestamp order")
            # As a last resort, sort by timestamp
            pending.parts.sort(key=lambda m: m.timestamp)

    except Exception as e:
        logger.warning(f"Failed to sort message parts: {e}", exc_info=e)


def create_merged_message(pending: PendingMessage) -> SMSMessage:
    """Create a merged message from all parts using proper ordering."""
    # For standard messages with part indicators like (1/3), (2/3), (3/3)
    # We want to extract just the content without the indicators
    parts_with_content: list[str] = []

    # Ensure parts are properly sorted before merging
    sort_message_parts(pending)

    # Check if we have UDH information
    has_udh = any(part.udh_info for part in pending.parts)

    for part in pending.parts:
        text = part.text

        if has_udh:
            # For UDH messages, use the text as is
            parts_with_content.append(text)
            continue

        # Try to remove part indicators like (1/3) from the beginning
        part_info = extract_part_info(text)
        if part_info:
            # Find the closing parenthesis of the part indicator and extract content after it
            try:
                match = re.match(r"^\s*\(\d+/\d+\)(.*)", text)
                if match:
                    content = match.group(1).strip()
                    parts_with_content.append(content)
                    continue
            except (ValueError, IndexError, AttributeError):
                pass

        # No part indicator or failed to remove it, use the full text
        parts_with_content.append(text)

    # Join the parts with intelligent handling for carrier-split messages
    merged_text = ""
    for i, part in enumerate(parts_with_content):
        # For the first part, add it as is
        if i == 0:
            merged_text += part
        # For later parts, check if we need to add a space
        # If the previous part ends with a complete word and this part starts with a new word,
        # we need to add a space to maintain proper spacing
        elif merged_text and merged_text[-1].isalnum() and part and part[0].isalnum():
            merged_text += " " + part
        else:
            # Otherwise concatenate (for mid-word splits)
            merged_text += part

    original_message = pending.message

    # Create a new message with merged content
    return SMSMessage(
        index=f"{original_message.index}_merged_{len(pending.parts)}",
        sender=original_message.sender,
        text=merged_text,
        timestamp=original_message.timestamp,
        is_alphanumeric=original_message.is_alphanumeric,
        sender_type=original_message.sender_type,
        udh_info=None,  # Clear UDH info as this is a merged message
    )


def is_message_complete(pending: PendingMessage) -> bool:
    """Check if a multipart message is complete using metadata.

    :param pending: The pending message information.
    :return: True if the message appears to be complete.
    """
    # First, check UDH information (most reliable)
    udh_parts = {}
    total_parts_udh = 0

    for part in pending.parts:
        if part.udh_info:
            ref_num = part.udh_info["ref_num"]
            current = part.udh_info["current_part"]
            total = part.udh_info["total_parts"]

            if ref_num not in udh_parts:
                udh_parts[ref_num] = {"parts": set(), "total": total}

            udh_parts[ref_num]["parts"].add(current)
            total_parts_udh = max(total_parts_udh, total)

    # Check if any reference number has all its parts
    for ref_data in udh_parts.values():
        if len(ref_data["parts"]) == ref_data["total"]:
            logger.info(f"Message complete based on UDH: {len(ref_data['parts'])}/{ref_data['total']} parts")
            return True

    # Check if we have all expected parts (from any source)
    if pending.expected_parts and len(pending.parts) >= pending.expected_parts:
        logger.info(f"Message complete: {len(pending.parts)}/{pending.expected_parts} parts")
        return True

    # Check text-based part indicators
    parts_with_info = []
    max_parts = 0

    for part in pending.parts:
        part_info = extract_part_info(part.text)
        if part_info:
            current, total = part_info
            max_parts = max(max_parts, total)
            parts_with_info.append(current)

    # If we have part information and all parts are present
    if 0 < max_parts == len(parts_with_info) and set(parts_with_info) == set(range(1, max_parts + 1)):
        logger.info(f"Message complete based on text indicators: all {max_parts} parts received")
        return True

    return False


def should_notify_multipart(pending: PendingMessage, is_complete: bool) -> bool:
    """Check if we should send a notification for a multipart message.

    :param pending: The pending message information
    :param is_complete: Whether the message is complete
    :return: True if notification should be sent
    """
    # Always notify when a message is complete
    if is_complete:
        return True

    # For partial messages, only notify if not already notified
    return not pending.notified


def is_single_message(sms: SMSMessage) -> bool:
    """Check if SMS is a single complete message (not multipart).

    :param sms: The SMS message to check
    :return: True if this is a single complete message
    """
    # Check for UDH information
    if sms.udh_info:
        return False

    # Check for explicit part markers
    part_info = extract_part_info(sms.text)
    if part_info:
        return False

    # Check message length against limits - if it is very close to the limit,
    # it is likely a multipart message even without explicit markers
    is_unicode = any(ord(c) > UNICODE_CHAR_THRESHOLD for c in sms.text)
    sms_limit = UNICODE_SMS_LENGTH if is_unicode else ASCII_SMS_LENGTH

    # If the message length is ≥ 90% of the limit, treat it as potentially multipart
    if len(sms.text) >= int(sms_limit * 0.9):
        return False

    return True
