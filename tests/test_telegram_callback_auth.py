"""Confirm/Undo callbacks are honoured only from the configured chat and allow-listed users (cnds#27)."""

from unittest.mock import AsyncMock, patch

import pytest

from src.guardian import telegram_listener as tl


def _cb(user_id, chat_id, data="undo:1"):
    return {"id": "cb1", "data": data, "from": {"id": user_id}, "message": {"chat": {"id": chat_id}}}


def _auth(cb, chat="111", allowed=()):
    with patch.object(tl, "TELEGRAM_CHAT_ID", chat), patch.object(tl, "TELEGRAM_ALLOWED_USER_IDS", set(allowed)):
        return tl._callback_authorized(cb)


def test_private_chat_owner_is_allowed_by_default():
    assert _auth(_cb(111, 111))


def test_other_user_in_private_chat_id_is_refused():
    assert not _auth(_cb(222, 111))


def test_callback_from_another_chat_is_refused_even_for_an_allowed_user():
    assert not _auth(_cb(111, 999), allowed={"111"})


def test_group_chat_without_allowlist_refuses_everyone():
    assert not _auth(_cb(111, -100123), chat="-100123")


def test_group_chat_allowlist():
    assert _auth(_cb(111, -100123), chat="-100123", allowed={"111"})
    assert not _auth(_cb(222, -100123), chat="-100123", allowed={"111"})


def test_malformed_callback_is_refused():
    assert not _auth({"id": "x", "data": "undo:1"})


@pytest.mark.asyncio
async def test_unauthorized_callback_never_touches_the_database():
    with patch.object(tl, "TELEGRAM_CHAT_ID", "111"), patch.object(tl, "TELEGRAM_ALLOWED_USER_IDS", set()), \
         patch.object(tl, "AsyncSessionLocal") as session, \
         patch.object(tl, "_answer_callback", new=AsyncMock()) as answer:
        await tl._handle_callback(AsyncMock(), _cb(222, 111))
    session.assert_not_called()
    assert answer.call_args.args[2] == "Not authorized."
