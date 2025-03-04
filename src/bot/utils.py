import asyncio
import logging
import re

from collections.abc import Awaitable, Callable

import phonenumbers

from config import get_settings
from phonenumbers import NumberParseException
from telegram import Update
from telegram.error import NetworkError, RetryAfter, TimedOut
from telegram.ext import ContextTypes


settings = get_settings()

logger = logging.getLogger(__name__)


async def retry_telegram_api[ReturnType: any, **P](
    func: Callable[P, Awaitable[ReturnType]], *args: P.args, max_retries: int = 3, **kwargs: P.kwargs
) -> ReturnType | None:
    """
    Retry a Telegram API call with exponential backoff.

    :param func: The async function to call
    :param max_retries: Maximum number of retries
    :return: The result of the function call
    """
    retries: int = 0
    last_exception: Exception | None = None

    while retries < max_retries:
        try:
            return await func(*args, **kwargs)
        except (TimedOut, NetworkError) as e:
            last_exception = e
            retries += 1
            wait_time = 2**retries  # Exponential backoff
            logger.warning(
                f"Telegram API error: {e}. Retrying in {wait_time} seconds... (Attempt {retries}/{max_retries})"
            )
            await asyncio.sleep(wait_time)
        except RetryAfter as e:
            last_exception = e
            # Use the time specified by Telegram
            wait_time = e.retry_after
            logger.warning(f"Telegram API rate limit. Retrying in {wait_time} seconds...")
            await asyncio.sleep(wait_time)

    # If we've exhausted retries, raise the last exception
    if last_exception:
        logger.error(f"Failed after {max_retries} retries: {last_exception}")
        raise last_exception


def is_valid_phone_number(phone_number: str) -> bool:
    """
    Check if a string looks like a valid phone number using pydantic's PhoneNumber validation.

    :param phone_number: The phone number to validate
    :return: True if the phone number appears valid, False otherwise
    """
    try:
        # Try to parse the phone number
        parsed = phonenumbers.parse(phone_number, settings.modem.default_region)
        return phonenumbers.is_valid_number(parsed)
    except NumberParseException:
        return False


def format_phone_number(phone_number: str) -> str:
    """
    Format a phone number for SMS sending using the phonenumbers library.

    :param phone_number: The phone number to format
    :return: The formatted phone number in international format
    """
    try:
        # Parse and format the phone number
        parsed = phonenumbers.parse(phone_number, settings.modem.default_region)
        if phonenumbers.is_valid_number(parsed):
            return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)

        # If not valid, fall back to basic formatting
        raise ValueError("Invalid phone number")
    except (ValueError, NumberParseException):
        # Fallback to basic formatting if parsing fails.
        # Remove common formatting characters
        cleaned = re.sub(r"[\s\-().]", "", phone_number)

        # Ensure it has a + prefix for international format if it doesn't already
        if not cleaned.startswith("+"):
            cleaned = "+" + cleaned

        return cleaned


def extract_sender_from_message(message_text: str) -> str | None:
    """
    Extract sender information from a message text.

    :param message_text: The message text to parse
    :return: The extracted sender or None if not found
    """
    # Try a pattern with asterisks (Markdown formatting)
    sender_match = re.search(r"\*From:\* ([^\n]+)", message_text)
    if sender_match:
        return sender_match.group(1)

    # Try a pattern without asterisks
    sender_match = re.search(r"From: ([^\n]+)", message_text)
    if sender_match:
        return sender_match.group(1)

    # Try to find a phone number directly
    phone_match = re.search(r"\+\d+", message_text)
    if phone_match:
        return phone_match.group(0)

    return None


async def unauthorized_response(update: Update) -> None:
    """
    Send a response to unauthorized users.

    :param update: The update from an unauthorized user
    """
    msg = update.effective_message
    user = update.effective_user

    if not msg:
        return
    await msg.reply_text("You are not authorized to use this bot.")

    if user:
        logger.warning(f"Unauthorized access attempt by user {user.id} ({user.username})")
        return
    logger.warning("Unauthorized access attempt by unknown user")


async def check_access(update: Update) -> bool:
    user = update.effective_user
    if not user:
        return False
    if user.id != settings.bot.allowed_user_id:
        await unauthorized_response(update)
        return False
    return True


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Handle errors in the telegram-bot-python library.

    :param update: The update that caused the error.
    :param context: The context for this handler.
    """
    logger.error("Exception while handling an update:", exc_info=context.error)

    # Get the error message
    error_message = str(context.error)

    # Send an error message to the user if this is a modem-related error
    if (
        isinstance(update, Update)
        and update.effective_message
        and update.effective_user
        and update.effective_user.id == settings.bot.allowed_user_id
    ):
        await update.effective_message.reply_text(f"Error: {error_message}")
