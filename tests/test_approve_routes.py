"""AUD-04-38 (DD-385 Phase W wave 2) — ts_approve_routes read-merge semantics.

The Tailscale v2 set-routes endpoint REPLACES the device's enabled-route set.
The tool must therefore additively approve by default (GET current routes,
POST the union) and only replace when explicitly asked via ``replace=true``.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

import tailscale_blade_mcp.server as server_module


def _mock_client(enabled: list[str], advertised: list[str] | None = None) -> AsyncMock:
    client = AsyncMock()
    client.get_device_routes.return_value = {
        "advertisedRoutes": advertised if advertised is not None else list(enabled),
        "enabledRoutes": list(enabled),
    }
    client.set_device_routes.return_value = None
    return client


class TestApproveRoutesMerge:
    @pytest.mark.asyncio
    async def test_existing_routes_preserved(self, mock_env_write: None) -> None:
        """Default call merges: previously-enabled routes survive the approval."""
        client = _mock_client(enabled=["10.0.0.0/24", "192.168.1.0/24"])
        with patch.object(server_module, "_get_client", return_value=client):
            out = await server_module.ts_approve_routes(device_id="nABC123", routes=["172.16.0.0/16"])
        client.get_device_routes.assert_awaited_once_with("nABC123")
        client.set_device_routes.assert_awaited_once_with("nABC123", ["10.0.0.0/24", "192.168.1.0/24", "172.16.0.0/16"])
        assert "10.0.0.0/24" in out
        assert "172.16.0.0/16" in out
        assert "1 newly approved, 2 preserved" in out

    @pytest.mark.asyncio
    async def test_duplicate_request_is_idempotent(self, mock_env_write: None) -> None:
        """Re-approving an already-enabled route does not duplicate it."""
        client = _mock_client(enabled=["10.0.0.0/24"])
        with patch.object(server_module, "_get_client", return_value=client):
            out = await server_module.ts_approve_routes(device_id="nABC123", routes=["10.0.0.0/24"])
        client.set_device_routes.assert_awaited_once_with("nABC123", ["10.0.0.0/24"])
        assert "0 newly approved, 1 preserved" in out

    @pytest.mark.asyncio
    async def test_empty_current_routes(self, mock_env_write: None) -> None:
        """No currently-enabled routes: union is exactly the requested set."""
        client = _mock_client(enabled=[])
        with patch.object(server_module, "_get_client", return_value=client):
            out = await server_module.ts_approve_routes(device_id="nABC123", routes=["192.168.1.0/24"])
        client.get_device_routes.assert_awaited_once_with("nABC123")
        client.set_device_routes.assert_awaited_once_with("nABC123", ["192.168.1.0/24"])
        assert "1 newly approved, 0 preserved" in out

    @pytest.mark.asyncio
    async def test_null_enabled_routes_collapses_to_empty(self, mock_env_write: None) -> None:
        """Live API can emit null lists — must not crash the merge."""
        client = AsyncMock()
        client.get_device_routes.return_value = {
            "advertisedRoutes": None,
            "enabledRoutes": None,
        }
        with patch.object(server_module, "_get_client", return_value=client):
            await server_module.ts_approve_routes(device_id="nABC123", routes=["10.1.0.0/24"])
        client.set_device_routes.assert_awaited_once_with("nABC123", ["10.1.0.0/24"])


class TestApproveRoutesReplace:
    @pytest.mark.asyncio
    async def test_replace_true_skips_merge(self, mock_env_write: None) -> None:
        """replace=True POSTs exactly the requested set, no GET."""
        client = _mock_client(enabled=["10.0.0.0/24", "192.168.1.0/24"])
        with patch.object(server_module, "_get_client", return_value=client):
            out = await server_module.ts_approve_routes(device_id="nABC123", routes=["172.16.0.0/16"], replace=True)
        client.get_device_routes.assert_not_awaited()
        client.set_device_routes.assert_awaited_once_with("nABC123", ["172.16.0.0/16"])
        assert "Replaced" in out
        assert "de-approved" in out

    @pytest.mark.asyncio
    async def test_replace_true_empty_routes_clears_all(self, mock_env_write: None) -> None:
        """replace=True with [] is the explicit clear-all path."""
        client = _mock_client(enabled=["10.0.0.0/24"])
        with patch.object(server_module, "_get_client", return_value=client):
            out = await server_module.ts_approve_routes(device_id="nABC123", routes=[], replace=True)
        client.set_device_routes.assert_awaited_once_with("nABC123", [])
        assert "(none)" in out


class TestApproveRoutesGate:
    @pytest.mark.asyncio
    async def test_write_gate_blocks(self, mock_env: None) -> None:
        client = _mock_client(enabled=["10.0.0.0/24"])
        with patch.object(server_module, "_get_client", return_value=client):
            out = await server_module.ts_approve_routes(device_id="nABC123", routes=["172.16.0.0/16"])
        client.get_device_routes.assert_not_awaited()
        client.set_device_routes.assert_not_awaited()
        assert "TAILSCALE_WRITE_ENABLED" in out
