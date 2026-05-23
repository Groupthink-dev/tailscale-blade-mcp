"""DD-338 Phase B.1.b — determinism harness for 4 multi-record tools.

Each tool MUST emit byte-equal output across N=5 calls against a fixed mocked
upstream. Sort-key correctness cases verify the canonical key is honoured.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

import tailscale_blade_mcp.server as server_module


N_RUNS = 5


def _byte_equal(outputs: list[str]) -> None:
    first = outputs[0]
    for i, o in enumerate(outputs[1:], start=1):
        assert o == first, f"Non-deterministic on run {i}: {o!r} vs {first!r}"


# ---------------------------------------------------------------------------
# ts_devices — sort by nodeId asc (id tie-break)
# ---------------------------------------------------------------------------


def _make_device(node_id: str, name: str = "host", legacy_id: str | None = None) -> dict[str, Any]:
    return {
        "nodeId": node_id,
        "id": legacy_id if legacy_id is not None else node_id.replace("n", ""),
        "name": f"{name}.tail.ts.net",
        "hostname": name,
        "os": "macOS",
        "addresses": ["100.100.1.1"],
        "clientVersion": "1.76.1",
        "updateAvailable": False,
        "created": "2025-01-15T10:00:00Z",
        "lastSeen": "2026-04-11T12:00:00Z",
        "connectedToControl": True,
        "authorized": True,
        "isExternal": False,
        "isEphemeral": False,
        "keyExpiryDisabled": False,
        "expires": "2026-07-11T10:00:00Z",
        "tags": [],
        "user": "u@example.com",
    }


class TestTsDevicesDeterministic:
    @pytest.mark.asyncio
    async def test_byte_equal_n5(self, mock_env: None) -> None:
        fixture = [
            _make_device("nzzz999", "z-host"),
            _make_device("naaa111", "a-host"),
            _make_device("nmmm555", "m-host"),
        ]
        outputs: list[str] = []
        for _ in range(N_RUNS):
            with patch.object(server_module, "_get_client") as mock_gc:
                mock_client = AsyncMock()
                mock_client.get_devices.return_value = [dict(d) for d in fixture]
                mock_gc.return_value = mock_client
                outputs.append(await server_module.ts_devices())
        _byte_equal(outputs)

    @pytest.mark.asyncio
    async def test_sorts_by_node_id_ascending(self, mock_env: None) -> None:
        fixture = [
            _make_device("nzzz", "z"),
            _make_device("naaa", "a"),
            _make_device("nmmm", "m"),
        ]
        with patch.object(server_module, "_get_client") as mock_gc:
            mock_client = AsyncMock()
            mock_client.get_devices.return_value = [dict(d) for d in fixture]
            mock_gc.return_value = mock_client
            out = await server_module.ts_devices()
        # Each device renders by nodeId
        assert out.index("naaa") < out.index("nmmm") < out.index("nzzz")

    @pytest.mark.asyncio
    async def test_falls_back_to_legacy_id(self, mock_env: None) -> None:
        # Devices without nodeId — sort key falls back to legacy `id`. The
        # formatter renders by hostname; we observe ordering via hostname order
        # in the output (legacy id ordering should still produce deterministic
        # name ordering since names track the id ordering in this fixture).
        fixture = [
            {**_make_device("", "host-z"), "nodeId": "", "id": "99999"},
            {**_make_device("", "host-a"), "nodeId": "", "id": "11111"},
        ]
        with patch.object(server_module, "_get_client") as mock_gc:
            mock_client = AsyncMock()
            mock_client.get_devices.return_value = [dict(d) for d in fixture]
            mock_gc.return_value = mock_client
            out = await server_module.ts_devices()
        # legacy id "11111" sorts before "99999"; corresponding hostnames
        # appear in the same order in the rendered output.
        assert out.index("host-a") < out.index("host-z")


# ---------------------------------------------------------------------------
# ts_keys — sort by id asc
# ---------------------------------------------------------------------------


def _make_key(key_id: str, tags: list[str] | None = None) -> dict[str, Any]:
    return {
        "id": key_id,
        "description": f"key {key_id}",
        "expires": "2027-01-01T00:00:00Z",
        "created": "2026-01-01T00:00:00Z",
        "capabilities": {
            "devices": {
                "create": {
                    "reusable": False,
                    "ephemeral": False,
                    "preauthorized": True,
                    "tags": tags or [],
                }
            }
        },
    }


class TestTsKeysDeterministic:
    @pytest.mark.asyncio
    async def test_byte_equal_n5(self, mock_env: None) -> None:
        fixture = [
            _make_key("zzz_key_id"),
            _make_key("aaa_key_id"),
            _make_key("mmm_key_id"),
        ]
        outputs: list[str] = []
        for _ in range(N_RUNS):
            with patch.object(server_module, "_get_client") as mock_gc:
                mock_client = AsyncMock()
                mock_client.get_keys.return_value = [dict(k) for k in fixture]
                mock_gc.return_value = mock_client
                outputs.append(await server_module.ts_keys())
        _byte_equal(outputs)

    @pytest.mark.asyncio
    async def test_sorts_by_id_ascending(self, mock_env: None) -> None:
        fixture = [
            _make_key("zzz"),
            _make_key("aaa"),
        ]
        with patch.object(server_module, "_get_client") as mock_gc:
            mock_client = AsyncMock()
            mock_client.get_keys.return_value = [dict(k) for k in fixture]
            mock_gc.return_value = mock_client
            out = await server_module.ts_keys()
        assert out.index("aaa") < out.index("zzz")


# ---------------------------------------------------------------------------
# ts_users — sort by case-folded loginName asc (id tie-break)
# ---------------------------------------------------------------------------


def _make_user(login: str, user_id: str | None = None, display: str | None = None) -> dict[str, Any]:
    return {
        "id": user_id or login.replace("@", "_at_"),
        "displayName": display or login.split("@")[0].title(),
        "loginName": login,
        "type": "member",
        "role": "member",
        "status": "active",
        "deviceCount": 1,
        "lastSeen": "2026-04-11T12:00:00Z",
        "currentlyConnected": True,
    }


class TestTsUsersDeterministic:
    @pytest.mark.asyncio
    async def test_byte_equal_n5(self, mock_env: None) -> None:
        fixture = [
            _make_user("Zara@example.com"),
            _make_user("alpha@example.com"),
            _make_user("Mid@example.com"),
        ]
        outputs: list[str] = []
        for _ in range(N_RUNS):
            with patch.object(server_module, "_get_client") as mock_gc:
                mock_client = AsyncMock()
                mock_client.get_users.return_value = [dict(u) for u in fixture]
                mock_gc.return_value = mock_client
                outputs.append(await server_module.ts_users())
        _byte_equal(outputs)

    @pytest.mark.asyncio
    async def test_sorts_case_folded_login_name(self, mock_env: None) -> None:
        # Mixed-case loginNames — case-folded sort should treat Z and a comparably.
        fixture = [
            _make_user("Zara@example.com"),
            _make_user("alpha@example.com"),
        ]
        with patch.object(server_module, "_get_client") as mock_gc:
            mock_client = AsyncMock()
            mock_client.get_users.return_value = [dict(u) for u in fixture]
            mock_gc.return_value = mock_client
            out = await server_module.ts_users()
        # Case-folded: 'alpha' < 'zara'
        assert out.index("alpha@example.com") < out.index("Zara@example.com")

    @pytest.mark.asyncio
    async def test_id_tiebreak_on_same_login(self, mock_env: None) -> None:
        # Pathological — same loginName, different ids. Should fall through to id tie-break.
        fixture = [
            _make_user("same@example.com", user_id="9999"),
            _make_user("same@example.com", user_id="1111"),
        ]
        with patch.object(server_module, "_get_client") as mock_gc:
            mock_client = AsyncMock()
            mock_client.get_users.return_value = [dict(u) for u in fixture]
            mock_gc.return_value = mock_client
            # Should not raise. Tie-break order is on id.
            out = await server_module.ts_users()
            assert "same@example.com" in out


# ---------------------------------------------------------------------------
# ts_webhooks — sort by endpointId asc
# ---------------------------------------------------------------------------


def _make_webhook(endpoint_id: str) -> dict[str, Any]:
    return {
        "endpointId": endpoint_id,
        "endpointUrl": f"https://example.com/webhook/{endpoint_id}",
        "providerType": "slack",
        "subscriptions": ["nodeCreated"],
        "created": "2026-01-01T00:00:00Z",
        "lastModified": "2026-04-01T00:00:00Z",
        "secret": None,
    }


class TestTsWebhooksDeterministic:
    @pytest.mark.asyncio
    async def test_byte_equal_n5(self, mock_env: None) -> None:
        fixture = [
            _make_webhook("wh_zzz"),
            _make_webhook("wh_aaa"),
            _make_webhook("wh_mmm"),
        ]
        outputs: list[str] = []
        for _ in range(N_RUNS):
            with patch.object(server_module, "_get_client") as mock_gc:
                mock_client = AsyncMock()
                mock_client.get_webhooks.return_value = [dict(w) for w in fixture]
                mock_gc.return_value = mock_client
                outputs.append(await server_module.ts_webhooks())
        _byte_equal(outputs)

    @pytest.mark.asyncio
    async def test_sorts_by_endpoint_id(self, mock_env: None) -> None:
        fixture = [
            _make_webhook("wh_zzz"),
            _make_webhook("wh_aaa"),
        ]
        with patch.object(server_module, "_get_client") as mock_gc:
            mock_client = AsyncMock()
            mock_client.get_webhooks.return_value = [dict(w) for w in fixture]
            mock_gc.return_value = mock_client
            out = await server_module.ts_webhooks()
        assert out.index("wh_aaa") < out.index("wh_zzz")
