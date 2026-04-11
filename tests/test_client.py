"""Tests for Tailscale client wrapper."""

from __future__ import annotations

import pytest

from tailscale_blade_mcp.client import TailscaleClient, _scrub


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
