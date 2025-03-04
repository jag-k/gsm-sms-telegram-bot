import datetime
import logging
import string

from typing import TypedDict

import messaging.sms

from sms_reader.models import SMSMessage, UDHInfo


logger = logging.getLogger(__name__)


class ParseTextModeResponse(TypedDict):
    header: str
    text: str


def parse_text_mode_response(response_text: str) -> list[ParseTextModeResponse]:
    """Parse the AT+CMGL response into a list of SMS entries.

    :param response_text: Raw response from AT+CMGL command
    :return: List of dictionaries with header and text fields
    """
    sms_entries: list[ParseTextModeResponse] = []
    current_entry: ParseTextModeResponse | None = None

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
            # Log UDH information for debugging
            logger.debug(f"UDH: {sms.udh}")

            # Check for concatenation information
            if hasattr(sms.udh, "concat") and sms.udh.concat:
                udh_info = UDHInfo(
                    ref_num=sms.udh.concat.ref,  # Reference number
                    total_parts=sms.udh.concat.cnt,  # Total number of parts
                    current_part=sms.udh.concat.seq,  # Current part number (sequence)
                )
                logger.debug(
                    f"Found multipart SMS: part {udh_info.current_part}/{udh_info.total_parts}, ref: {udh_info.ref_num}"
                )

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
