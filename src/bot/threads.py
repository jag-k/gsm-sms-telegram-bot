import asyncio
import logging

import telegram

from bot.utils import normalize_recipient, retry_telegram_api
from config import get_settings
from telegram import ForumTopic
from telegram.ext import Application


settings = get_settings()
logger = logging.getLogger(__name__)

THREAD_TITLE_MAX_LENGTH = 128
_CREATING_THREAD_SENTINEL = -1


class ThreadManager:
    """Manages forum topic threads mapped to phone numbers."""

    def __init__(self, app: Application, bot_data_lock: asyncio.Lock) -> None:
        self._app = app
        self._lock = bot_data_lock

    def _get_chat_data(self, chat_id: int) -> dict:
        """
        Return the ``chat_data`` dict for the given chat ID.

        :param chat_id: The Telegram chat ID.
        :return: The mutable chat data dict.
        """
        return self._app.chat_data[chat_id]

    async def _check_private_topics_enabled(self, chat_id: int, *, force_check: bool = False) -> bool:
        """
        Check if Threaded Mode is enabled for the bot in private chats.

        ``User.has_topics_enabled`` is only returned by ``bot.get_me()`` (Bot API 9.3+).
        The result is cached in ``chat_data`` and survives restarts.
        Enable via BotFather → Bot Settings → Threads Settings → Threaded Mode.

        :param chat_id: The private chat ID to cache the result under.
        :param force_check: If True, bypass the cached value and re-query ``get_me``.
        :return: True if the bot has Threaded Mode enabled.
        """
        chat_data = self._get_chat_data(chat_id)
        if not force_check and "topics_enabled" in chat_data:
            return bool(chat_data["topics_enabled"])
        try:
            me: telegram.User | None = await retry_telegram_api(self._app.bot.get_me)
            if not me:
                logger.warning("get_me returned None; cannot check private topics")
                return False
        except Exception as e:
            logger.warning("Failed to fetch bot info for private topics check", exc_info=e)
            return False
        has_topics: bool | None = me.has_topics_enabled
        logger.debug("Bot get_me: has_topics_enabled=%r", has_topics)
        result = bool(has_topics)
        chat_data["topics_enabled"] = result
        return result

    async def are_topics_enabled(
        self,
        chat: telegram.Chat | None = None,
        *,
        force_check: bool = False,
    ) -> bool:
        """
        Check if topics are enabled for the target chat.

        For supergroups, uses ``Chat.is_forum``.
        For private chats, uses ``User.has_topics_enabled`` from ``bot.get_me()``
        (Bot API 9.3+, enabled via BotFather → Threads Settings → Threaded Mode).

        The result is cached in ``chat_data`` and persisted across restarts.

        :param chat: The chat object from ``update.effective_chat``. When provided,
            no extra ``get_chat`` API call is made. Falls back to
            ``get_chat(allowed_user_id)`` when omitted (e.g. for incoming SMS).
        :param force_check: If True, bypass the cached value and re-query the Telegram API.
        :return: True if topics are enabled, False otherwise.
        """
        if chat is None:
            try:
                chat = await retry_telegram_api(
                    self._app.bot.get_chat,
                    chat_id=settings.bot.allowed_user_id,
                )
            except Exception as e:
                logger.warning("Failed to fetch chat info for topics check; disabling topics", exc_info=e)
                return False

        if not chat:
            logger.warning("Chat info unavailable for topics check; disabling topics")
            return False

        chat_data = self._get_chat_data(chat.id)
        if not force_check and "topics_enabled" in chat_data:
            return bool(chat_data["topics_enabled"])

        if chat.type == telegram.Chat.PRIVATE:
            return await self._check_private_topics_enabled(chat.id, force_check=force_check)

        is_forum: bool | None = chat.is_forum
        logger.debug("Chat %s (type=%s): is_forum=%r", chat.id, chat.type, is_forum)
        topics_enabled = bool(is_forum)
        chat_data["topics_enabled"] = topics_enabled
        if not topics_enabled:
            logger.warning(
                "Topics are disabled for this chat (id=%s, type=%s); falling back to General chat",
                chat.id,
                chat.type,
            )
        return topics_enabled

    @staticmethod
    def _build_thread_title(phone_number: str, display_name: str | None) -> str:
        """
        Build a thread title combining the display name and identifier.

        :param phone_number: The normalized phone number or sender ID.
        :param display_name: The display name to include.
        :return: The thread title.
        """
        if not display_name:
            return phone_number
        display_name = display_name.strip()
        if not display_name:
            return phone_number

        title = f"{display_name} ({phone_number})"
        if len(title) <= THREAD_TITLE_MAX_LENGTH:
            return title

        available = THREAD_TITLE_MAX_LENGTH - len(phone_number) - 3
        if available <= 0:
            return phone_number[:THREAD_TITLE_MAX_LENGTH]

        truncated_name = display_name[:available].rstrip()
        return f"{truncated_name} ({phone_number})"

    async def _get_phone_display_name(self, normalized_phone: str) -> str | None:
        """
        Get a display name for a phone number.

        :param normalized_phone: The already-normalized phone number to look up.
        :return: The display name or None.
        """
        bot_data = self._app.bot_data
        async with self._lock:
            phone_display_names: dict[str, str] = bot_data.setdefault("phone_display_names", {})
            return phone_display_names.get(normalized_phone)

    async def _get_thread_title(self, phone_number: str) -> str:
        """
        Build a thread title for the phone number using any stored display name.

        :param phone_number: The phone number to use.
        :return: The thread title.
        """
        normalized_phone = normalize_recipient(phone_number)
        display_name = await self._get_phone_display_name(normalized_phone)
        return self._build_thread_title(normalized_phone, display_name)

    async def _create_thread(self, normalized_phone: str) -> int | None:
        """
        Create a new thread for the normalized phone number.

        :param normalized_phone: The phone number in normalized form.
        :return: The thread ID or None if creation failed.
        """
        try:
            thread_title = await self._get_thread_title(normalized_phone)
            topic: ForumTopic | None = await retry_telegram_api(
                self._app.bot.create_forum_topic,
                chat_id=settings.bot.allowed_user_id,
                name=thread_title,
            )
        except Exception as e:
            logger.warning(f"Failed to create topic for {normalized_phone}: {e}", exc_info=e)
            return None

        if not topic:
            logger.warning(f"Topic creation returned no data for {normalized_phone}")
            return None
        thread_id = topic.message_thread_id
        if thread_id is None:
            logger.warning(f"Topic creation returned no thread id for {normalized_phone}")
            return None
        return thread_id

    async def get_or_create_thread(self, phone_number: str) -> int | None:
        """
        Get or create a forum topic thread for a phone number.

        :param phone_number: The phone number to map to a thread.
        :return: The thread ID or None if topics are unavailable.
        """
        if not await self.are_topics_enabled():
            return None

        normalized_phone = normalize_recipient(phone_number)
        bot_data = self._app.bot_data

        async with self._lock:
            phone_threads: dict[str, int] = bot_data.setdefault("phone_threads", {})
            thread_id = phone_threads.get(normalized_phone)

        if thread_id is not None and thread_id != _CREATING_THREAD_SENTINEL:
            return thread_id

        if thread_id == _CREATING_THREAD_SENTINEL:
            return None

        async with self._lock:
            phone_threads[normalized_phone] = _CREATING_THREAD_SENTINEL

        thread_id = await self._create_thread(normalized_phone)

        async with self._lock:
            if thread_id is None:
                phone_threads.pop(normalized_phone, None)
            else:
                phone_threads[normalized_phone] = thread_id
                thread_phones: dict[int, str] = bot_data.setdefault("thread_phones", {})
                thread_phones[thread_id] = normalized_phone

        return thread_id

    async def get_thread_id(self, phone_number: str) -> int | None:
        """
        Get existing thread ID for a phone number without creating one.

        :param phone_number: The phone number to look up.
        :return: The thread ID or None if no thread exists.
        """
        normalized = normalize_recipient(phone_number)
        async with self._lock:
            phone_threads: dict[str, int] = self._app.bot_data.setdefault("phone_threads", {})
            thread_id = phone_threads.get(normalized)
        if thread_id == _CREATING_THREAD_SENTINEL:
            return None
        return thread_id

    async def rename_thread(self, thread_id: int, phone_number: str, display_name: str) -> None:
        """
        Rename an existing thread to include the display name.

        :param thread_id: The thread ID to rename.
        :param phone_number: The phone number in normalized form.
        :param display_name: The display name to use.
        """
        if not await self.are_topics_enabled():
            return

        title = self._build_thread_title(phone_number, display_name)
        try:
            await retry_telegram_api(
                self._app.bot.edit_forum_topic,
                chat_id=settings.bot.allowed_user_id,
                message_thread_id=thread_id,
                name=title,
            )
        except Exception as e:
            logger.warning(f"Failed to rename thread for {phone_number}: {e}", exc_info=e)

    async def set_phone_display_name(self, phone_number: str, display_name: str) -> None:
        """
        Store display name for a phone number and update thread title if needed.

        :param phone_number: The phone number to update.
        :param display_name: The display name to store.
        """
        cleaned_name = display_name.strip()
        if not cleaned_name:
            return

        normalized_phone = normalize_recipient(phone_number)
        bot_data = self._app.bot_data

        async with self._lock:
            phone_display_names: dict[str, str] = bot_data.setdefault("phone_display_names", {})
            phone_threads: dict[str, int] = bot_data.setdefault("phone_threads", {})
            phone_display_names[normalized_phone] = cleaned_name
            thread_id = phone_threads.get(normalized_phone)

        if thread_id is None:
            return
        await self.rename_thread(thread_id, normalized_phone, cleaned_name)

    async def get_phone_for_thread_id(self, thread_id: int) -> str | None:
        """
        Get a phone number associated with a thread ID.

        :param thread_id: The message thread ID.
        :return: The phone number or None if not found.
        """
        bot_data = self._app.bot_data
        async with self._lock:
            thread_phones: dict[int, str] = bot_data.setdefault("thread_phones", {})
            return thread_phones.get(thread_id)
