"""Tests for models and configuration parsing."""

from __future__ import annotations

import pytest

from tailscale_blade_mcp.models import (
    is_write_enabled,
    parse_config,
    require_write,
)


class TestParseConfig:
    def test_minimal_config(self, mock_env: None) -> None:
        config = parse_config()
        assert config.api_key == "tskey-api-test123"
        assert config.tailnet == "-"
        assert config.api_base == "https://api.tailscale.com/api/v2"

    def test_custom_tailnet(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TAILSCALE_API_KEY", "tskey-api-test")
        monkeypatch.setenv("TAILSCALE_TAILNET", "example.com")
        config = parse_config()
        assert config.tailnet == "example.com"

    def test_custom_api_base(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TAILSCALE_API_KEY", "tskey-api-test")
        monkeypatch.setenv("TAILSCALE_API_BASE", "https://custom.api.example.com/v2")
        config = parse_config()
        assert config.api_base == "https://custom.api.example.com/v2"

    def test_missing_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TAILSCALE_API_KEY", raising=False)
        with pytest.raises(ValueError, match="API key not configured"):
            parse_config()

    def test_empty_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TAILSCALE_API_KEY", "  ")
        with pytest.raises(ValueError, match="API key not configured"):
            parse_config()


class TestWriteGate:
    def test_disabled_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TAILSCALE_WRITE_ENABLED", raising=False)
        assert not is_write_enabled()
        assert require_write() is not None
        assert "disabled" in require_write().lower()  # type: ignore[union-attr]

    def test_enabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TAILSCALE_WRITE_ENABLED", "true")
        assert is_write_enabled()
        assert require_write() is None

    def test_case_insensitive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TAILSCALE_WRITE_ENABLED", "TRUE")
        assert is_write_enabled()

    def test_false_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TAILSCALE_WRITE_ENABLED", "false")
        assert not is_write_enabled()
