"""MCP client tests — httpx.MockTransport, koi live network call nahi."""

from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

import httpx

from toing import (
    TELEGRAM_CHUNK,
    McpClient,
    McpToolError,
    ReauthRequiredError,
    ScopeError,
    Session,
    SessionExpiredError,
    SessionStore,
    TokenClient,
    format_tools_dump,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def initialize_response(body: dict) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "jsonrpc": "2.0",
            "id": body["id"],
            "result": fixture("initialize.json")["result"],
        },
        headers={"Mcp-Session-Id": "sess-abc"},
    )


class McpClientTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.store = SessionStore(Path(self.temp_dir.name) / "session.json")
        self.store.save(
            Session(
                client_id="swiggy-mcp",
                access_token="tok-old",
                refresh_token="ref-old",
                expires_at=time.time() + 3600,
            )
        )

    def make_client(self, handler) -> McpClient:
        http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        self.addAsyncCleanup(http.aclose)
        return McpClient(TokenClient(http, self.store), self.store)

    async def test_initialize_notification_and_session_id(self) -> None:
        calls: list[tuple[str, dict, str | None]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            calls.append(
                (
                    str(body.get("method")),
                    body,
                    request.headers.get("Mcp-Session-Id"),
                )
            )
            method = body.get("method")
            if method == "initialize":
                return initialize_response(body)
            if method == "notifications/initialized":
                return httpx.Response(202)
            if method == "tools/list":
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": body["id"],
                        "result": {
                            "tools": [
                                {
                                    "name": "get_addresses",
                                    "description": "addresses",
                                    "inputSchema": {"type": "object"},
                                }
                            ]
                        },
                    },
                )
            return httpx.Response(500, json={"error": "unexpected"})

        client = self.make_client(handler)
        tools = await client.list_tools()

        self.assertEqual(
            [entry[0] for entry in calls],
            ["initialize", "notifications/initialized", "tools/list"],
        )
        init_body = calls[0][1]
        self.assertEqual(init_body["params"]["protocolVersion"], "2025-06-18")
        self.assertEqual(init_body["params"]["capabilities"], {})
        self.assertEqual(
            init_body["params"]["clientInfo"], {"name": "toing", "version": "1.0.0"}
        )
        self.assertIsNone(calls[0][2])
        self.assertNotIn("id", calls[1][1])
        self.assertEqual(calls[2][2], "sess-abc")
        self.assertEqual(client.session_id, "sess-abc")
        self.assertEqual([tool["name"] for tool in tools], ["get_addresses"])

    async def test_sse_response_parsed_by_request_id(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            method = body.get("method")
            if method == "initialize":
                return initialize_response(body)
            if method == "notifications/initialized":
                return httpx.Response(202)
            if method == "tools/call":
                noise = {
                    "jsonrpc": "2.0",
                    "id": 99,
                    "result": {
                        "content": [{"type": "text", "text": '{"noise": true}'}]
                    },
                }
                matching = {
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {
                        "content": [
                            {"type": "text", "text": '{"addresses": []}'}
                        ]
                    },
                }
                stream = (
                    f"data: {json.dumps(noise)}\n\n"
                    f"data: {json.dumps(matching)}\n"
                )
                return httpx.Response(
                    200,
                    text=stream,
                    headers={"Content-Type": "text/event-stream"},
                )
            return httpx.Response(500)

        client = self.make_client(handler)
        result = await client.call_tool("get_addresses", {"page": 1, "size": 10})
        self.assertEqual(result, {"addresses": []})

    async def test_401_refreshes_rotates_and_retries(self) -> None:
        seen_auth: list[str | None] = []

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            if request.url.path == "/auth/token":
                self.assertEqual(body["grant_type"], "refresh_token")
                self.assertEqual(body["refresh_token"], "ref-old")
                return httpx.Response(
                    200,
                    json={
                        "access_token": "tok-new",
                        "refresh_token": "ref-new",
                        "token_type": "Bearer",
                        "expires_in": 2592000,
                    },
                )
            method = body.get("method")
            if method == "initialize":
                return initialize_response(body)
            if method == "notifications/initialized":
                return httpx.Response(202)
            if method == "tools/call":
                seen_auth.append(request.headers.get("Authorization"))
                if request.headers.get("Authorization") == "Bearer tok-new":
                    return httpx.Response(
                        200,
                        json={
                            "jsonrpc": "2.0",
                            "id": body["id"],
                            "result": {
                                "content": [
                                    {"type": "text", "text": '{"ok": true}'}
                                ]
                            },
                        },
                    )
                return httpx.Response(
                    401, json={"error": "invalid_token"}
                )
            return httpx.Response(500)

        client = self.make_client(handler)
        result = await client.call_tool("get_food_cart", {})
        self.assertEqual(result, {"ok": True})
        self.assertEqual(
            seen_auth, ["Bearer tok-old", "Bearer tok-new"]
        )
        self.assertEqual(self.store.load().refresh_token, "ref-new")

    async def test_refresh_failure_raises_clean_session_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            if request.url.path == "/auth/token":
                return httpx.Response(
                    400, json={"error": "invalid_grant"}
                )
            method = body.get("method")
            if method == "initialize":
                return initialize_response(body)
            if method == "notifications/initialized":
                return httpx.Response(202)
            return httpx.Response(401, json={"error": "invalid_token"})

        client = self.make_client(handler)
        with self.assertRaises(SessionExpiredError) as context:
            await client.call_tool("get_food_cart", {})
        self.assertEqual(
            str(context.exception), "session expire — naya session.json bhejo"
        )

    async def test_rpc_error_32001_triggers_refresh_retry(self) -> None:
        token_calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal token_calls
            body = json.loads(request.content)
            if request.url.path == "/auth/token":
                token_calls += 1
                return httpx.Response(
                    200,
                    json={
                        "access_token": "tok-new",
                        "refresh_token": "ref-new",
                        "token_type": "Bearer",
                        "expires_in": 2592000,
                    },
                )
            method = body.get("method")
            if method == "initialize":
                return initialize_response(body)
            if method == "notifications/initialized":
                return httpx.Response(202)
            if method == "tools/call":
                if request.headers.get("Authorization") == "Bearer tok-new":
                    return httpx.Response(
                        200,
                        json={
                            "jsonrpc": "2.0",
                            "id": body["id"],
                            "result": {
                                "content": [
                                    {"type": "text", "text": '{"ok": true}'}
                                ]
                            },
                        },
                    )
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": body["id"],
                        "error": {
                            "code": -32001,
                            "message": "unauthorized",
                        },
                    },
                )
            return httpx.Response(500)

        client = self.make_client(handler)
        result = await client.call_tool("get_food_cart", {})
        self.assertEqual(result, {"ok": True})
        self.assertEqual(token_calls, 1)

    async def test_tool_is_error_raises_swiggy_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            method = body.get("method")
            if method == "initialize":
                return initialize_response(body)
            if method == "notifications/initialized":
                return httpx.Response(202)
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": '{"message": "item out of stock"}',
                            }
                        ],
                        "isError": True,
                    },
                },
            )

        client = self.make_client(handler)
        with self.assertRaises(McpToolError) as context:
            await client.call_tool("update_food_cart", {"item_id": "x"})
        self.assertIn("Swiggy error:", str(context.exception))
        self.assertIn("item out of stock", str(context.exception))

    async def test_proactive_refresh_when_under_60_seconds(self) -> None:
        self.store.save(
            Session(
                client_id="swiggy-mcp",
                access_token="tok-old",
                refresh_token="ref-old",
                expires_at=time.time() + 30,
            )
        )
        order: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            if request.url.path == "/auth/token":
                order.append("token")
                return httpx.Response(
                    200,
                    json={
                        "access_token": "tok-new",
                        "refresh_token": "ref-new",
                        "token_type": "Bearer",
                        "expires_in": 2592000,
                    },
                )
            order.append("food")
            method = body.get("method")
            if method == "initialize":
                return initialize_response(body)
            if method == "notifications/initialized":
                return httpx.Response(202)
            self.assertEqual(
                request.headers.get("Authorization"), "Bearer tok-new"
            )
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "result": {
                        "content": [{"type": "text", "text": '{"ok": true}'}]
                    },
                },
            )

        client = self.make_client(handler)
        result = await client.call_tool("get_food_cart", {})
        self.assertEqual(result, {"ok": True})
        self.assertEqual(order[0], "token")

    async def test_list_tools_paginates_with_cursor(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            method = body.get("method")
            if method == "initialize":
                return initialize_response(body)
            if method == "notifications/initialized":
                return httpx.Response(202)
            if method == "tools/list":
                cursor = body.get("params", {}).get("cursor")
                if not cursor:
                    return httpx.Response(
                        200,
                        json={
                            "jsonrpc": "2.0",
                            "id": body["id"],
                            "result": {
                                "tools": [{"name": "tool_one"}],
                                "nextCursor": "page-2",
                            },
                        },
                    )
                self.assertEqual(cursor, "page-2")
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": body["id"],
                        "result": {"tools": [{"name": "tool_two"}]},
                    },
                )
            return httpx.Response(500)

        client = self.make_client(handler)
        tools = await client.list_tools()
        self.assertEqual(
            [tool["name"] for tool in tools], ["tool_one", "tool_two"]
        )

    async def test_419_and_403_have_clear_messages(self) -> None:
        def handler_419(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            if body.get("method") == "initialize":
                return httpx.Response(419)
            return httpx.Response(500)

        client = self.make_client(handler_419)
        with self.assertRaises(ReauthRequiredError) as context:
            await client.list_tools()
        self.assertIn("login", str(context.exception))

        def handler_403(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            if body.get("method") == "initialize":
                return httpx.Response(403)
            return httpx.Response(500)

        client = self.make_client(handler_403)
        with self.assertRaises(ScopeError) as context:
            await client.list_tools()
        self.assertIn("scope", str(context.exception))


class ToolsDumpTests(unittest.TestCase):
    def test_dump_chunks_fit_telegram_limit(self) -> None:
        tools = [
            {
                "name": f"tool_{index}",
                "description": f"description {index}",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        f"arg_{index}": {"type": "string", "description": "x" * 200}
                    },
                },
            }
            for index in range(20)
        ]
        chunks = format_tools_dump(tools)
        self.assertTrue(chunks)
        for chunk in chunks:
            self.assertLessEqual(len(chunk), TELEGRAM_CHUNK + 200)
        joined = "\n".join(chunks)
        for index in range(20):
            self.assertIn(f"tool_{index}", joined)
        self.assertIn("inputSchema", joined)


if __name__ == "__main__":
    unittest.main()
