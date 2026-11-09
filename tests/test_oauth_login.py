"""OAuth (DCR + PKCE) login tests — MockTransport, koi live network call nahi."""

from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx

from toing import (
    Session,
    SessionExpiredError,
    SessionStore,
    ToingError,
    _login_async,
    build_authorize_url,
    challenge_of,
    ensure_pending,
    extract_code,
    finish_login,
    new_pkce,
    pending_authorize_url,
    validate_session_payload,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class PkceTests(unittest.TestCase):
    def test_verifier_and_challenge_shape(self) -> None:
        verifier, challenge = new_pkce()
        self.assertEqual(len(verifier), 43)
        self.assertEqual(len(challenge), 43)
        self.assertNotIn("=", verifier + challenge)
        self.assertEqual(challenge, challenge_of(verifier))
        other_verifier, _ = new_pkce()
        self.assertNotEqual(verifier, other_verifier)

    def test_authorize_url_contains_all_params(self) -> None:
        url = build_authorize_url("swiggy-mcp", "chal-123", "state-xyz")
        self.assertTrue(
            url.startswith("https://mcp.swiggy.com/auth/authorize?")
        )
        query = parse_qs(urlsplit(url).query)
        self.assertEqual(query["response_type"], ["code"])
        self.assertEqual(query["client_id"], ["swiggy-mcp"])
        self.assertEqual(query["redirect_uri"], ["http://localhost/callback"])
        self.assertEqual(query["code_challenge"], ["chal-123"])
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["state"], ["state-xyz"])
        self.assertEqual(query["scope"], ["mcp:tools"])

    def test_extract_code_paths(self) -> None:
        self.assertEqual(extract_code("plaincode123", "s"), "plaincode123")
        url = "http://localhost/callback?code=abc123&state=match"
        self.assertEqual(extract_code(url, "match"), "abc123")
        with self.assertRaises(ToingError):
            extract_code("http://localhost/callback?state=match", "match")
        with self.assertRaises(ToingError):
            extract_code(
                "http://localhost/callback?code=abc&state=WRONG", "match"
            )
        with self.assertRaises(ToingError):
            extract_code("   ", "match")


class TokenClientTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.base = Path(self.temp_dir.name)
        self.store = SessionStore(self.base / "session.json")
        self.workdir = self.base / "work"
        self.workdir.mkdir()
        self.previous_cwd = Path.cwd()
        os.chdir(self.workdir)
        self.addCleanup(os.chdir, self.previous_cwd)

    def make_token_client(self, handler):
        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        self.addAsyncCleanup(http.aclose)
        from toing import TokenClient

        return TokenClient(http, self.store)

    async def test_register_sends_exact_body(self) -> None:
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["path"] = request.url.path
            captured["body"] = json.loads(request.content)
            return httpx.Response(
                201, json={"client_id": "swiggy-mcp", "client_name": "toing"}
            )

        client = self.make_token_client(handler)
        client_id = await client.register()
        self.assertEqual(client_id, "swiggy-mcp")
        self.assertEqual(captured["path"], "/auth/register")
        body = captured["body"]
        self.assertEqual(body["client_name"], "toing")
        self.assertEqual(body["redirect_uris"], ["http://localhost/callback"])
        self.assertEqual(
            body["grant_types"], ["authorization_code", "refresh_token"]
        )
        self.assertEqual(body["response_types"], ["code"])
        self.assertEqual(body["token_endpoint_auth_method"], "none")
        self.assertEqual(body["scope"], "mcp:tools")

    async def test_exchange_saves_session_with_600_perms(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            self.assertEqual(body["grant_type"], "authorization_code")
            self.assertEqual(body["code"], "the-code")
            self.assertEqual(body["code_verifier"], "the-verifier")
            self.assertEqual(body["redirect_uri"], "http://localhost/callback")
            return httpx.Response(200, json=fixture("token.json"))

        client = self.make_token_client(handler)
        session = await client.exchange_code(
            "swiggy-mcp", "the-code", "the-verifier"
        )
        saved = self.store.load()
        self.assertEqual(saved.client_id, "swiggy-mcp")
        self.assertEqual(saved.access_token, "eyJtest-access-token")
        self.assertEqual(saved.refresh_token, "eyJtest-refresh-token")
        self.assertEqual(session.access_token, saved.access_token)
        self.assertGreater(saved.expires_at, time.time() + 431000)
        mode = self.store.path.stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    async def test_refresh_rotates_and_persists(self) -> None:
        self.store.save(
            Session(
                client_id="swiggy-mcp",
                access_token="tok-old",
                refresh_token="ref-old",
                expires_at=time.time() + 100,
            )
        )

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            self.assertEqual(
                body, {"grant_type": "refresh_token", "refresh_token": "ref-old"}
            )
            self.assertNotIn("Authorization", request.headers)
            return httpx.Response(
                200,
                json={
                    "access_token": "tok-2",
                    "refresh_token": "ref-2",
                    "token_type": "Bearer",
                    "expires_in": 2592000,
                },
            )

        client = self.make_token_client(handler)
        await client.refresh(self.store.load())
        self.assertEqual(self.store.load().refresh_token, "ref-2")

    async def test_refresh_failure_raises_session_expired(self) -> None:
        self.store.save(
            Session(
                client_id="swiggy-mcp",
                access_token="tok-old",
                refresh_token="ref-old",
                expires_at=time.time() + 100,
            )
        )

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, json={"error": "invalid_grant"})

        client = self.make_token_client(handler)
        with self.assertRaises(SessionExpiredError) as context:
            await client.refresh(self.store.load())
        self.assertEqual(
            str(context.exception), "session expire — naya session.json bhejo"
        )

    def test_validate_session_payload_errors(self) -> None:
        valid = {
            "client_id": "swiggy-mcp",
            "access_token": "a",
            "refresh_token": "r",
            "expires_at": time.time() + 100,
        }
        session = validate_session_payload(valid)
        self.assertEqual(session.client_id, "swiggy-mcp")
        with self.assertRaises(ToingError):
            validate_session_payload(["not", "a", "dict"])
        with self.assertRaises(ToingError):
            validate_session_payload({**valid, "access_token": ""})
        with self.assertRaises(ToingError):
            validate_session_payload({**valid, "refresh_token": None})
        with self.assertRaises(ToingError):
            validate_session_payload({**valid, "expires_at": True})
        with self.assertRaises(ToingError):
            validate_session_payload({**valid, "expires_at": -5})


class LoginFlowTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.previous_cwd = Path.cwd()
        os.chdir(self.temp_dir.name)
        self.addCleanup(os.chdir, self.previous_cwd)

    async def test_full_login_flow_writes_valid_session(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/auth/register":
                return httpx.Response(201, json={"client_id": "swiggy-mcp"})
            if path == "/auth/token":
                body = json.loads(request.content)
                self.assertEqual(body["grant_type"], "authorization_code")
                self.assertEqual(body["code"], "the-code")
                pending = json.loads(
                    Path(".login_pending.json").read_text(encoding="utf-8")
                )
                self.assertEqual(body["code_verifier"], pending["code_verifier"])
                self.assertEqual(body["redirect_uri"], "http://localhost/callback")
                return httpx.Response(200, json=fixture("token.json"))
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        step_one = await _login_async(
            None, transport=transport, interactive=False
        )
        self.assertEqual(step_one, 0)
        self.assertTrue(Path(".login_pending.json").is_file())
        pending = json.loads(
            Path(".login_pending.json").read_text(encoding="utf-8")
        )
        self.assertEqual(pending["client_id"], "swiggy-mcp")
        self.assertEqual(len(pending["code_verifier"]), 43)

        callback_url = (
            f"http://localhost/callback?code=the-code&state={pending['state']}"
        )
        step_two = await _login_async(callback_url, transport=transport)
        self.assertEqual(step_two, 0)
        self.assertTrue(Path("session.json").is_file())
        self.assertFalse(Path(".login_pending.json").exists())
        saved = json.loads(Path("session.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["access_token"], "eyJtest-access-token")
        self.assertEqual(saved["refresh_token"], "eyJtest-refresh-token")
        self.assertEqual(saved["client_id"], "swiggy-mcp")
        self.assertGreater(saved["expires_at"], time.time() + 431000)
        mode = Path("session.json").stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    async def test_ensure_pending_and_finish_login_pipeline(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path == "/auth/register":
                return httpx.Response(201, json={"client_id": "swiggy-mcp"})
            if path == "/auth/token":
                body = json.loads(request.content)
                self.assertEqual(body["grant_type"], "authorization_code")
                self.assertEqual(body["code"], "the-code")
                pending = json.loads(
                    Path(".login_pending.json").read_text(encoding="utf-8")
                )
                self.assertEqual(body["code_verifier"], pending["code_verifier"])
                return httpx.Response(200, json=fixture("token.json"))
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as http:
            pending = await ensure_pending(http)
            self.assertEqual(pending["client_id"], "swiggy-mcp")
            url = pending_authorize_url(pending)
            self.assertIn("code_challenge=", url)
            self.assertIn(pending["state"], url)
            session = await finish_login(
                http,
                "http://localhost/callback?code=the-code&state=" + pending["state"],
            )
        self.assertEqual(session.access_token, "eyJtest-access-token")
        self.assertFalse(Path(".login_pending.json").exists())
        self.assertTrue(Path("session.json").is_file())

    async def test_finish_login_without_pending_raises(self) -> None:
        async with httpx.AsyncClient() as http:
            with self.assertRaises(ToingError) as context:
                await finish_login(http, "http://localhost/callback?code=x")
        self.assertIn("Login session nahi mila", str(context.exception))

    async def test_finish_login_state_mismatch_raises(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(201, json={"client_id": "swiggy-mcp"})

        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport) as http:
            await ensure_pending(http)
            with self.assertRaises(ToingError):
                await finish_login(
                    http,
                    "http://localhost/callback?code=the-code&state=WRONG",
                )
        self.assertTrue(Path(".login_pending.json").exists())


if __name__ == "__main__":
    unittest.main()
