"""Tests for Tailscale client wrapper."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from tailscale_blade_mcp.client import (
    PolicyError,
    PreconditionFailedError,
    TailscaleClient,
    _scrub,
)

ACL_URL = "https://api.tailscale.com/api/v2/tailnet/-/acl"


class TestCredentialScrubbing:
    def test_scrub_api_key(self) -> None:
        assert "REDACTED" in _scrub("key=tskey-api-abc123def456")

    def test_scrub_bearer(self) -> None:
        assert "REDACTED" in _scrub("Bearer tskey-api-abc123")

    def test_scrub_authorization_header(self) -> None:
        assert "REDACTED" in _scrub("Authorization: Bearer secret123")

    def test_scrub_token_field(self) -> None:
        assert "REDACTED" in _scrub("token=secret-value-123")

    def test_scrub_preserves_safe_text(self) -> None:
        safe = "Connection timeout after 30s"
        assert _scrub(safe) == safe

    def test_scrub_multiple_patterns(self) -> None:
        msg = "Bearer tskey-api-abc token=xyz"
        scrubbed = _scrub(msg)
        assert "tskey-api-abc" not in scrubbed
        assert "xyz" not in scrubbed


class TestTailscaleClientInit:
    def test_creates_with_config(self, mock_env: None) -> None:
        client = TailscaleClient()
        assert client.config.api_key == "tskey-api-test123"
        assert client.config.tailnet == "-"

    def test_missing_api_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TAILSCALE_API_KEY", raising=False)
        with pytest.raises(ValueError, match="API key not configured"):
            TailscaleClient()

    def test_http_client_lazy(self, mock_env: None) -> None:
        client = TailscaleClient()
        assert client._http is None

    def test_tailnet_path(self, mock_env: None) -> None:
        client = TailscaleClient()
        assert client._tailnet_path("devices") == "/tailnet/-/devices"

    def test_custom_tailnet_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TAILSCALE_API_KEY", "tskey-api-test")
        monkeypatch.setenv("TAILSCALE_TAILNET", "example.com")
        client = TailscaleClient()
        assert client._tailnet_path("devices") == "/tailnet/example.com/devices"


@pytest.mark.anyio
class TestAclSetClient:
    """Client-level ACL apply + ETag surfacing (respx-mocked HTTP)."""

    @pytest.fixture
    def anyio_backend(self) -> str:
        return "asyncio"

    @respx.mock
    async def test_get_acl_with_etag_surfaces_header(self, mock_env: None) -> None:
        respx.get(ACL_URL).mock(return_value=Response(200, json={"acls": []}, headers={"ETag": "etag-abc"}))
        client = TailscaleClient()
        policy, etag = await client.get_acl_with_etag()
        assert policy == {"acls": []}
        assert etag == "etag-abc"
        await client.close()

    @respx.mock
    async def test_get_acl_with_etag_missing_header(self, mock_env: None) -> None:
        respx.get(ACL_URL).mock(return_value=Response(200, json={"acls": []}))
        client = TailscaleClient()
        _policy, etag = await client.get_acl_with_etag()
        assert etag is None
        await client.close()

    @respx.mock
    async def test_set_acl_returns_new_etag(self, mock_env: None) -> None:
        route = respx.post(ACL_URL).mock(return_value=Response(200, json={"acls": []}, headers={"ETag": "etag-2"}))
        client = TailscaleClient()
        applied, etag = await client.set_acl({"acls": []}, if_match="etag-1")
        assert applied == {"acls": []}
        assert etag == "etag-2"
        assert route.calls.last.request.headers.get("if-match") == "etag-1"
        await client.close()

    @respx.mock
    async def test_set_acl_412_raises_precondition(self, mock_env: None) -> None:
        respx.post(ACL_URL).mock(return_value=Response(412, text="precondition failed"))
        client = TailscaleClient()
        with pytest.raises(PreconditionFailedError, match="ETag mismatch"):
            await client.set_acl({"acls": []}, if_match="stale")
        await client.close()

    @respx.mock
    async def test_set_acl_400_raises_policy_error_scrubbed(self, mock_env: None) -> None:
        respx.post(ACL_URL).mock(return_value=Response(400, text="bad policy near Bearer tskey-api-leak"))
        client = TailscaleClient()
        with pytest.raises(PolicyError) as excinfo:
            await client.set_acl({"acls": []})
        msg = str(excinfo.value)
        assert "400" in msg
        assert "tskey-api-leak" not in msg
        assert "REDACTED" in msg
        await client.close()
