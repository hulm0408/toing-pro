#!/usr/bin/env python3
"""toing.py — Swiggy MCP ordering bot (single file).

Subcommands:
    python toing.py login   OAuth (DCR + PKCE) login -> session.json (0600)
    python toing.py bot     Telegram bot

Menu, price aur payment kuch bhi local nahi hai — sab kuch user ke apne
Swiggy account se Swiggy ke official MCP server se aata hai:

    POST https://mcp.swiggy.com/food   (JSON-RPC 2.0, Bearer token)
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import html
import json
import logging
import os
import secrets
import sys
import time
import traceback
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
from dotenv import load_dotenv

BASE_URL = "https://mcp.swiggy.com"
FOOD_ENDPOINT = f"{BASE_URL}/food"
REGISTER_ENDPOINT = f"{BASE_URL}/auth/register"
AUTHORIZE_ENDPOINT = f"{BASE_URL}/auth/authorize"
TOKEN_ENDPOINT = f"{BASE_URL}/auth/token"

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "toing", "version": "1.0.0"}
SCOPE = "mcp:tools"
REDIRECT_URI = "http://localhost/callback"
ACCEPT_HEADER = "application/json, text/event-stream"

SESSION_PATH = Path("session.json")
PENDING_LOGIN_PATH = Path(".login_pending.json")
LOCK_PATH = Path("toing.pid.lock")
LOG_PATH = Path("toing.log")

ACCESS_TOKEN_LIFETIME_SECONDS = 5 * 24 * 3600
REFRESH_MARGIN_SECONDS = 60
SESSION_UPLOAD_MAX_BYTES = 64 * 1024
TELEGRAM_CHUNK = 3900
PAYMENT_POLL_INTERVAL_SECONDS = 3
PAYMENT_POLL_MAX_ATTEMPTS = 60

logger = logging.getLogger("toing")


class ToingError(Exception):
    """Base error — user ko sirf yeh message dikhana hai."""


class SessionExpiredError(ToingError):
    """Refresh fail — user ko naya session.json chahiye."""


class ReauthRequiredError(ToingError):
    """419 — session revoke; full re-login chahiye."""


class ScopeError(ToingError):
    """403 — token scope narrow hai."""


class McpToolError(ToingError):
    """Tool ne isError=true return kiya."""


# --------------------------------------------------------------------------
# Session storage
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Session:
    client_id: str
    access_token: str
    refresh_token: str
    expires_at: float


def validate_session_payload(data: Any) -> Session:
    if not isinstance(data, dict):
        raise ToingError("session.json me JSON object hona chahiye.")
    client_id = data.get("client_id")
    access_token = data.get("access_token")
    refresh_token = data.get("refresh_token")
    expires_at = data.get("expires_at")
    if not isinstance(client_id, str) or not client_id.strip():
        raise ToingError("session.json me client_id missing hai.")
    if not isinstance(access_token, str) or not access_token.strip():
        raise ToingError("session.json me access_token missing hai.")
    if not isinstance(refresh_token, str) or not refresh_token.strip():
        raise ToingError("session.json me refresh_token missing hai.")
    if isinstance(expires_at, bool) or not isinstance(expires_at, (int, float)):
        raise ToingError("session.json me expires_at number hona chahiye.")
    if float(expires_at) <= 0:
        raise ToingError("session.json me expires_at invalid hai.")
    return Session(
        client_id=client_id.strip(),
        access_token=access_token.strip(),
        refresh_token=refresh_token.strip(),
        expires_at=float(expires_at),
    )


class SessionStore:
    def __init__(self, path: Path = SESSION_PATH) -> None:
        self.path = path

    def exists(self) -> bool:
        return self.path.is_file()

    def load(self) -> Session:
        if not self.path.is_file():
            raise SessionExpiredError(
                "session expire — naya session.json bhejo"
            )
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ToingError("session.json padha nahi ja saka; dobara login karo.") from exc
        return validate_session_payload(raw)

    def save(self, session: Session) -> None:
        payload = {
            "client_id": session.client_id,
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "expires_at": session.expires_at,
        }
        previous = os.umask(0o077)
        try:
            self.path.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        finally:
            os.umask(previous)
        self.path.chmod(0o600)


# --------------------------------------------------------------------------
# OAuth: DCR + PKCE (official Swiggy MCP flow)
# --------------------------------------------------------------------------


def new_pkce() -> tuple[str, str]:
    verifier = (
        base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    )
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode("ascii").rstrip("=")
    return verifier, challenge


def build_authorize_url(
    client_id: str, code_challenge: str, state: str
) -> str:
    query = urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": state,
            "scope": SCOPE,
        }
    )
    return f"{AUTHORIZE_ENDPOINT}?{query}"


def extract_code(pasted: str, expected_state: str) -> str:
    text = pasted.strip().strip("'\"")
    if not text:
        raise ToingError("Code khaali hai; callback URL ya code paste karo.")
    if "://" in text or "?" in text:
        query = parse_qs(urlsplit(text).query)
        codes = query.get("code")
        if not codes or not codes[0]:
            raise ToingError("URL me code nahi mila; URL bar se poora address copy karo.")
        states = query.get("state")
        if states and states[0] != expected_state:
            raise ToingError("State mismatch — login dobara chalao.")
        return codes[0]
    return text


class TokenClient:
    def __init__(
        self, http: httpx.AsyncClient, store: SessionStore | None = None
    ) -> None:
        self.http = http
        self.store = store if store is not None else SessionStore()

    async def register(self, client_name: str = "toing") -> str:
        body = {
            "client_name": client_name,
            "redirect_uris": [REDIRECT_URI],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": SCOPE,
        }
        response = await self.http.post(REGISTER_ENDPOINT, json=body)
        if response.status_code not in (200, 201):
            raise ToingError(
                f"client registration fail hui (HTTP {response.status_code})."
            )
        data = response.json()
        client_id = data.get("client_id")
        if not isinstance(client_id, str) or not client_id:
            raise ToingError("registration response me client_id nahi mila.")
        return client_id

    async def exchange_code(
        self, client_id: str, code: str, code_verifier: str
    ) -> Session:
        body = {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
            "redirect_uri": REDIRECT_URI,
        }
        response = await self.http.post(TOKEN_ENDPOINT, json=body)
        if response.status_code != 200:
            raise ToingError(
                f"code exchange fail hua (HTTP {response.status_code}); "
                "code shayad expire hai — login dobara chalao."
            )
        return self._session_from_response(client_id, response.json())

    async def refresh(self, session: Session) -> Session:
        body = {
            "grant_type": "refresh_token",
            "refresh_token": session.refresh_token,
        }
        response = await self.http.post(TOKEN_ENDPOINT, json=body)
        if response.status_code != 200:
            raise SessionExpiredError("session expire — naya session.json bhejo")
        return self._session_from_response(session.client_id, response.json())

    def _session_from_response(
        self, client_id: str, data: dict[str, Any]
    ) -> Session:
        access_token = data.get("access_token")
        refresh_token = data.get("refresh_token") or access_token
        expires_in = data.get("expires_in", ACCESS_TOKEN_LIFETIME_SECONDS)
        if not isinstance(access_token, str) or not access_token:
            raise ToingError("token response me access_token nahi mila.")
        if not isinstance(refresh_token, str) or not refresh_token:
            raise ToingError("token response me refresh_token nahi mila.")
        try:
            lifetime = float(expires_in)
        except (TypeError, ValueError) as exc:
            raise ToingError("token response me expires_in invalid hai.") from exc
        session = Session(
            client_id=client_id,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=time.time() + lifetime,
        )
        self.store.save(session)
        return session


# --------------------------------------------------------------------------
# MCP client: initialize -> notifications/initialized -> tools/call
# --------------------------------------------------------------------------


def parse_sse_events(body: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in body.splitlines():
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload:
            continue
        try:
            parsed = json.loads(payload)
        except ValueError as exc:
            raise ToingError("SSE data line valid JSON nahi hai.") from exc
        if isinstance(parsed, dict):
            events.append(parsed)
    return events


class McpClient:
    def __init__(
        self,
        token_client: TokenClient,
        store: SessionStore,
        endpoint: str = FOOD_ENDPOINT,
    ) -> None:
        self.token_client = token_client
        self.store = store
        self.endpoint = endpoint
        self.session_id: str | None = None
        self._next_id = 1
        self._initialized = False
        self._init_result: dict[str, Any] = {}

    async def _ensure_fresh_token(self, session: Session) -> Session:
        if session.expires_at - time.time() > REFRESH_MARGIN_SECONDS:
            return session
        try:
            refreshed = await self.token_client.refresh(session)
        except ToingError as exc:
            raise SessionExpiredError(
                "session expire — naya session.json bhejo"
            ) from exc
        logger.info("Token proactively refresh hua; rotation save ho gayi.")
        return refreshed

    def _headers(self, session: Session) -> dict[str, str]:
        headers = {
            "Authorization": f"Bearer {session.access_token}",
            "Accept": ACCEPT_HEADER,
            "Content-Type": "application/json",
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        return headers

    async def _decode_response(
        self, response: httpx.Response, request_id: int | None
    ) -> dict[str, Any]:
        session_id = response.headers.get("Mcp-Session-Id")
        if session_id:
            self.session_id = session_id
        if response.status_code == 419:
            raise ReauthRequiredError(
                "session revoke ho gayi — dobara `python toing.py login` "
                "chalao aur naya session.json bhejo."
            )
        if response.status_code == 403:
            raise ScopeError(
                "scope problem — `mcp:tools` scope ke saath dobara login karo."
            )
        if response.status_code == 401:
            raise _AuthRetryNeeded()
        if response.status_code >= 400:
            raise ToingError(
                f"Swiggy error: HTTP {response.status_code} — thodi der baad try karo."
            )
        content_type = response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            events = parse_sse_events(response.text)
            if request_id is None:
                return {"jsonrpc": "2.0", "result": None}
            for event in events:
                if event.get("id") == request_id:
                    return event
            raise ToingError("SSE response me matching request id nahi mila.")
        if not response.content:
            return {"jsonrpc": "2.0", "result": None}
        try:
            data = response.json()
        except ValueError as exc:
            raise ToingError("Swiggy response valid JSON nahi hai.") from exc
        if not isinstance(data, dict):
            raise ToingError("Swiggy response me JSON object nahi mila.")
        return data

    async def _rpc(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        notification: bool = False,
    ) -> Any:
        session = self.store.load()
        session = await self._ensure_fresh_token(session)
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        request_id: int | None = None
        if not notification:
            request_id = self._next_id
            self._next_id += 1
            body["id"] = request_id
        if params is not None:
            body["params"] = params

        for attempt in range(2):
            response = await self.token_client.http.post(
                self.endpoint, json=body, headers=self._headers(session)
            )
            try:
                data = await self._decode_response(response, request_id)
            except _AuthRetryNeeded:
                if attempt == 1:
                    raise SessionExpiredError(
                        "session expire — naya session.json bhejo"
                    ) from None
                try:
                    session = await self.token_client.refresh(session)
                except ToingError as exc:
                    raise SessionExpiredError(
                        "session expire — naya session.json bhejo"
                    ) from exc
                logger.info("401/-32001 par token refresh hua; request retry ho rahi hai.")
                continue
            error = data.get("error")
            if isinstance(error, dict):
                code = error.get("code")
                message = str(error.get("message", "unknown"))
                if code == -32001 and attempt == 0:
                    try:
                        session = await self.token_client.refresh(session)
                    except ToingError as exc:
                        raise SessionExpiredError(
                            "session expire — naya session.json bhejo"
                        ) from exc
                    logger.info("JSON-RPC -32001 par token refresh hua; retry ho raha hai.")
                    continue
                if code == -32001:
                    raise SessionExpiredError(
                        "session expire — naya session.json bhejo"
                    )
                raise ToingError(f"Swiggy error: {message}")
            if notification:
                return None
            return data.get("result")
        raise SessionExpiredError("session expire — naya session.json bhejo")

    async def initialize(self) -> dict[str, Any]:
        if self._initialized:
            return self._init_result
        result = await self._rpc(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": CLIENT_INFO,
            },
        )
        await self._rpc("notifications/initialized", notification=True)
        self._init_result = result if isinstance(result, dict) else {}
        self._initialized = True
        return self._init_result

    async def list_tools(self) -> list[dict[str, Any]]:
        await self.initialize()
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {"cursor": cursor} if cursor else {}
            result = await self._rpc("tools/list", params)
            if not isinstance(result, dict):
                raise ToingError("tools/list ka result invalid hai.")
            page = result.get("tools")
            if isinstance(page, list):
                tools.extend(item for item in page if isinstance(item, dict))
            cursor_value = result.get("nextCursor")
            if isinstance(cursor_value, str) and cursor_value:
                cursor = cursor_value
                continue
            return tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        await self.initialize()
        result = await self._rpc(
            "tools/call", {"name": name, "arguments": arguments}
        )
        if not isinstance(result, dict):
            raise ToingError(f"Swiggy error: {name} ka result invalid hai.")
        content = result.get("content")
        text = ""
        if isinstance(content, list) and content:
            first = content[0]
            if isinstance(first, dict) and isinstance(first.get("text"), str):
                text = first["text"]
        if result.get("isError"):
            raise McpToolError(f"Swiggy error: {self._tool_error_message(text)}")
        if not text:
            raise ToingError(f"Swiggy error: {name} se data nahi mila.")
        try:
            return json.loads(text)
        except ValueError:
            return {"raw": text}

    @staticmethod
    def _tool_error_message(text: str) -> str:
        try:
            data = json.loads(text)
        except ValueError:
            return text.strip()[:300] or "unknown error"
        if isinstance(data, dict):
            for key in ("message", "error", "detail"):
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()[:300]
            return json.dumps(data, ensure_ascii=False)[:300]
        return str(data)[:300]


class _AuthRetryNeeded(Exception):
    """Internal marker: 401 mila, refresh karke retry karo."""


# --------------------------------------------------------------------------
# Reusable runtime pieces: config, logging, admin alerts, PID lock
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BotConfig:
    bot_token: str
    admin_ids: frozenset[int]


def load_bot_config() -> BotConfig:
    load_dotenv()
    bot_token = os.environ.get("BOT_TOKEN", "").strip()
    admin_raw = os.environ.get("ADMIN_ID", "").strip()
    missing = []
    if not bot_token:
        missing.append("BOT_TOKEN")
    if not admin_raw:
        missing.append("ADMIN_ID")
    if missing:
        raise ToingError(
            "Required config missing: "
            + ", ".join(missing)
            + ". .env me set karo."
        )
    try:
        admin_id = int(admin_raw)
    except ValueError as exc:
        raise ToingError("ADMIN_ID numeric Telegram ID hona chahiye.") from exc
    if admin_id <= 0:
        raise ToingError("ADMIN_ID positive Telegram ID hona chahiye.")
    return BotConfig(bot_token=bot_token, admin_ids=frozenset({admin_id}))


def configure_logging() -> None:
    file_handler = RotatingFileHandler(
        LOG_PATH,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    console_handler = logging.StreamHandler()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        handlers=[file_handler, console_handler],
        force=True,
    )


class InstanceLock:
    def __init__(self, path: Path = LOCK_PATH) -> None:
        self.path = path
        self._file = None

    def acquire(self) -> None:
        handle = self.path.open("a+", encoding="ascii")
        try:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.seek(0)
            owner = handle.read().strip() or "unknown"
            handle.close()
            raise ToingError(
                f"Second poller allowed nahi hai; PID {owner} pehle se chal raha hai."
            ) from exc
        handle.seek(0)
        previous = handle.read().strip()
        if previous and previous.isdigit() and int(previous) != os.getpid():
            try:
                os.kill(int(previous), 0)
            except OSError:
                pass
            else:
                handle.close()
                raise ToingError(
                    f"Second poller allowed nahi hai; PID {previous} pehle se chal raha hai."
                )
        handle.seek(0)
        handle.truncate()
        handle.write(str(os.getpid()))
        handle.flush()
        self._file = handle

    def release(self) -> None:
        handle = self._file
        if handle is None:
            return
        self._file = None
        try:
            handle.seek(0)
            handle.truncate()
            handle.write("")
            handle.flush()
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


# --------------------------------------------------------------------------
# Telegram bot (reusable skeleton): /start, /schema, session upload
# --------------------------------------------------------------------------


def make_mcp_client(store: SessionStore) -> McpClient:
    http = httpx.AsyncClient(timeout=30.0)
    token_client = TokenClient(http, store)
    return McpClient(token_client, store)


def format_tools_dump(tools: list[dict[str, Any]]) -> list[str]:
    chunks: list[str] = []
    current: list[str] = []
    current_size = 0

    def flush() -> None:
        nonlocal current, current_size
        if current:
            chunks.append("\n".join(current))
            current = []
            current_size = 0

    for index, tool in enumerate(tools, start=1):
        name = str(tool.get("name", "unknown"))
        description = str(tool.get("description", "")).strip()
        schema = json.dumps(
            tool.get("inputSchema", {}), ensure_ascii=False, sort_keys=True
        )
        block = (
            f"{index}. {name}\n"
            f"{description[:300]}\n"
            f"inputSchema: {schema}"
        )
        if current_size + len(block) + 1 > TELEGRAM_CHUNK:
            flush()
        current.append(block)
        current_size += len(block) + 1
    flush()
    return chunks


def _clean_exception_message(exc: Exception) -> str:
    return html.escape(str(exc)[:400])


async def run_bot(config: BotConfig) -> None:
    from aiogram import Bot, Dispatcher, F, Router
    from aiogram.client.default import DefaultBotProperties
    from aiogram.enums import ParseMode
    from aiogram.filters import Command
    from aiogram.fsm.storage.memory import MemoryStorage
    from aiogram.types import (
        ErrorEvent,
        InlineKeyboardButton,
        InlineKeyboardMarkup,
        Message,
        ReplyKeyboardRemove,
    )

    store = SessionStore()
    error_router = Router(name="errors")
    router = Router(name="toing")

    @error_router.errors()
    async def unhandled_error_handler(event: ErrorEvent, bot: Bot) -> bool:
        exception = event.exception
        logger.error(
            "Unhandled Telegram update exception",
            exc_info=(type(exception), exception, exception.__traceback__),
        )
        text = "".join(
            traceback.format_exception(
                type(exception), exception, exception.__traceback__
            )
        )
        for admin_id in sorted(config.admin_ids):
            for start in range(0, len(text), TELEGRAM_CHUNK):
                chunk = text[start : start + TELEGRAM_CHUNK]
                try:
                    await bot.send_message(
                        admin_id,
                        "<b>Unhandled exception</b>\n"
                        f"<pre>{html.escape(chunk, quote=False)}</pre>",
                    )
                except Exception:
                    logger.exception("Admin ko traceback nahi bhej paye: %s", admin_id)
        return True

    @router.message(Command("start"))
    async def start_handler(message: Message) -> None:
        try:
            await message.answer(
                "<b>Toing — Swiggy ordering bot.</b>\n"
                "Menu, price, payment sab Swiggy ke official MCP server se — "
                "tumhare apne Swiggy account par.\n"
                "Pehle terminal me <code>python toing.py login</code> chalao, "
                "phir bana <code>session.json</code> yahan document bhejo.",
                reply_markup=ReplyKeyboardRemove(),
            )
        except Exception:
            logger.exception("/start failed")
            await message.answer("Start me dikkat aa gayi. Dobara /start karo.")

    @router.message(Command("schema"))
    async def schema_handler(message: Message) -> None:
        try:
            try:
                session = store.load()
            except ToingError as exc:
                await message.answer(str(exc))
                return
            client = make_mcp_client(store)
            try:
                tools = await client.list_tools()
                await message.answer(
                    f"Tools: {len(tools)} (Swiggy Food MCP)\n"
                    "Har tool ka naam + inputSchema neeche hai."
                )
                for chunk in format_tools_dump(tools):
                    await message.answer(f"<pre>{html.escape(chunk, quote=False)}</pre>")
                await message.answer(
                    f"Session client_id: <code>{html.escape(session.client_id)}</code>"
                )
            finally:
                await client.token_client.http.aclose()
        except ToingError as exc:
            await message.answer(str(exc))
        except Exception:
            logger.exception("/schema failed")
            await message.answer(
                "Schema load nahi hua. Thodi der baad dobara /schema karo."
            )

    @router.message(Command("login"))
    async def login_handler(message: Message) -> None:
        try:
            async with httpx.AsyncClient(timeout=30.0) as http:
                pending = await ensure_pending(http)
            url = pending_authorize_url(pending)
            keyboard = InlineKeyboardMarkup(
                inline_keyboard=[
                    [InlineKeyboardButton(text="🔐 Swiggy login kholo", url=url)]
                ]
            )
            await message.answer(
                "<b>Swiggy login — 3 steps</b>\n"
                "1. Neeche button se browser me login kholo — phone + OTP do.\n"
                "2. Page localhost par fail hoga — URL bar se poora address copy karo.\n"
                "3. <b>Woh URL yahin chat me paste kar do</b> "
                "(code ~2 min me expire hota hai, jaldi).\n\n"
                "Main khud session.json banaunga aur real /schema dump dunga.",
                reply_markup=keyboard,
            )
        except ToingError as exc:
            await message.answer(str(exc))
        except Exception:
            logger.exception("/login failed")
            await message.answer(
                "Login link nahi bana. Thodi der baad /login dobara karo."
            )

    @router.message(F.text.contains("code="))
    async def login_paste_handler(message: Message) -> None:
        try:
            pasted = (message.text or "").strip()
            async with httpx.AsyncClient(timeout=30.0) as http:
                session = await finish_login(http, pasted)
            expiry = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(session.expires_at)
            )
            await message.answer(
                "Login success ✅ session.json save ho gaya (0600 perms).\n"
                f"Access token <code>{html.escape(expiry)}</code> tak valid "
                "(refresh rotation on hai).\n"
                "Ab real /schema dump bhej raha hoon…"
            )
            client = make_mcp_client(SessionStore())
            try:
                tools = await client.list_tools()
                Path("schema_dump.json").write_text(
                    json.dumps(tools, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                await message.answer(
                    f"Tools: {len(tools)} (Swiggy Food MCP) — real /schema:"
                )
                for chunk in format_tools_dump(tools):
                    await message.answer(
                        f"<pre>{html.escape(chunk, quote=False)}</pre>"
                    )
                await message.answer(
                    "Schema save: <code>schema_dump.json</code>. "
                    "Ab main mini app + bot flow ko real Swiggy data se wire karunga."
                )
            finally:
                await client.token_client.http.aclose()
        except ToingError as exc:
            await message.answer(str(exc))
        except Exception:
            logger.exception("login paste failed")
            await message.answer(
                "Login complete nahi hua. /login se naya URL lekar dobara paste karo."
            )

    @router.message(F.document)
    async def document_handler(message: Message) -> None:
        try:
            document = message.document
            if document is None:
                await message.answer("File nahi mili. session.json dobara bhejo.")
                return
            file_name = (document.file_name or "").lower()
            if not file_name.endswith(".json"):
                await message.answer(
                    "Sirf session.json bhejo — login ke baad wahi file banti hai."
                )
                return
            if document.file_size and document.file_size > SESSION_UPLOAD_MAX_BYTES:
                await message.answer("File bahut badi hai; asli session.json bhejo.")
                return
            buffer = await message.bot.download(document)
            raw_bytes = buffer.read()
            try:
                payload = json.loads(raw_bytes.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                await message.answer(
                    "Ye valid session.json nahi hai — "
                    "<code>python toing.py login</code> se banao."
                )
                return
            try:
                session = validate_session_payload(payload)
            except ToingError as exc:
                await message.answer(str(exc))
                return
            store.save(session)
            logger.info(
                "Session upload save hua; client_id=%s", session.client_id
            )
            await message.answer(
                "session.json save ho gaya ✅\n"
                "Ordering flow yahan se aage badhega."
            )
        except Exception:
            logger.exception("session.json upload failed")
            await message.answer(
                "Session save nahi hua. session.json dobara bhejo."
            )

    bot = Bot(
        token=config.bot_token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dispatcher = Dispatcher(storage=MemoryStorage())
    dispatcher.include_router(error_router)
    dispatcher.include_router(router)
    lock = InstanceLock()
    lock.acquire()
    try:
        logger.info("Toing bot polling start ho raha hai; PID lock ready hai.")
        try:
            await dispatcher.start_polling(
                bot,
                allowed_updates=dispatcher.resolve_used_update_types(),
                handle_as_tasks=True,
                handle_signals=True,
                close_bot_session=False,
            )
        finally:
            tasks = tuple(getattr(dispatcher, "_handle_update_tasks", ()))
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        try:
            await bot.session.close()
        finally:
            lock.release()


# --------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------


def _load_pending() -> dict[str, Any] | None:
    if not PENDING_LOGIN_PATH.is_file():
        return None
    try:
        data = json.loads(PENDING_LOGIN_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def _save_pending(data: dict[str, Any]) -> None:
    previous = os.umask(0o077)
    try:
        PENDING_LOGIN_PATH.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    finally:
        os.umask(previous)
    PENDING_LOGIN_PATH.chmod(0o600)


async def ensure_pending(http: httpx.AsyncClient) -> dict[str, Any]:
    pending = _load_pending()
    if pending is not None:
        return pending
    token_client = TokenClient(http, SessionStore())
    client_id = await token_client.register()
    verifier, _challenge = new_pkce()
    state = secrets.token_urlsafe(24)
    pending = {
        "client_id": client_id,
        "code_verifier": verifier,
        "state": state,
        "created_at": time.time(),
    }
    _save_pending(pending)
    return pending


def pending_authorize_url(pending: dict[str, Any]) -> str:
    return build_authorize_url(
        str(pending["client_id"]),
        code_challenge=challenge_of(str(pending["code_verifier"])),
        state=str(pending["state"]),
    )


async def finish_login(http: httpx.AsyncClient, pasted: str) -> Session:
    pending = _load_pending()
    if pending is None:
        raise ToingError(
            "Login session nahi mila — pehle `python toing.py login` ya bot me /login chalao."
        )
    auth_code = extract_code(pasted, str(pending["state"]))
    token_client = TokenClient(http, SessionStore())
    try:
        session = await token_client.exchange_code(
            str(pending["client_id"]),
            auth_code,
            str(pending["code_verifier"]),
        )
    except ToingError as exc:
        raise ToingError(
            "Code exchange fail — code ~2 min me expire hota hai. "
            "Naya login URL kholo aur code jaldi paste karo."
        ) from exc
    PENDING_LOGIN_PATH.unlink(missing_ok=True)
    return session


async def _login_async(
    code: str | None,
    *,
    transport: httpx.AsyncTransport | None = None,
    interactive: bool | None = None,
) -> int:
    async with httpx.AsyncClient(timeout=30.0, transport=transport) as http:
        pending = await ensure_pending(http)
        url = pending_authorize_url(pending)

        print("Swiggy MCP login — 3 steps:")
        print()
        print("1. Browser me ye URL kholo:")
        print()
        print(url)
        print()
        print("2. Apne phone number se OTP do. Page localhost par fail hoga —")
        print("   URL bar se poora address copy karo (usme ?code=... hota hai).")
        print()

        pasted = code
        if pasted is None:
            can_prompt = sys.stdin.isatty() if interactive is None else interactive
            if can_prompt:
                pasted = input("3. Callback URL ya code yahan paste karo: ")
            else:
                print(
                    "Pending state save hai. Code milte hi chalao:\n"
                    "  python toing.py login --code '<callback-url-ya-code>'"
                )
                return 0

        session = await finish_login(http, pasted)
        expiry = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(session.expires_at)
        )
        print()
        print("Login success ✅  session.json save ho gaya (0600 perms).")
        print(f"Access token valid: {expiry} tak (refresh token rotate hota hai).")
        print("Ab `python toing.py bot` chalao aur session.json Telegram pe bhejo.")
        return 0


def challenge_of(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def cmd_login(args: argparse.Namespace) -> int:
    try:
        return asyncio.run(_login_async(args.code))
    except ToingError as exc:
        print(f"Login error: {exc}", file=sys.stderr)
        return 1


def cmd_bot(args: argparse.Namespace) -> int:
    try:
        config = load_bot_config()
        configure_logging()
    except ToingError as exc:
        raise SystemExit(f"Config error: {exc}") from exc
    try:
        asyncio.run(run_bot(config))
    except ToingError as exc:
        raise SystemExit(f"Instance error: {exc}") from exc
    except KeyboardInterrupt:
        logger.info("Toing bot band hua.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="toing.py", description="Swiggy MCP ordering bot"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    login_parser = subparsers.add_parser(
        "login", help="OAuth login (DCR + PKCE) -> session.json"
    )
    login_parser.add_argument(
        "--code",
        default=None,
        help="Callback URL ya code (warna prompt hoga)",
    )
    login_parser.set_defaults(func=cmd_login)

    bot_parser = subparsers.add_parser("bot", help="Telegram bot chalao")
    bot_parser.set_defaults(func=cmd_bot)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
