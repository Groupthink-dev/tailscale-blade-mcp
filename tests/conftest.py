"""Shared fixtures for Tailscale Blade MCP tests."""

from __future__ import annotations

from typing import Any

import pytest


@pytest.fixture()
def mock_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set minimal environment for single-tailnet config."""
    monkeypatch.setenv("TAILSCALE_API_KEY", "tskey-api-test123")
    monkeypatch.delenv("TAILSCALE_TAILNET", raising=False)
    monkeypatch.delenv("TAILSCALE_WRITE_ENABLED", raising=False)


@pytest.fixture()
def mock_env_write(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set environment with write enabled."""
    monkeypatch.setenv("TAILSCALE_API_KEY", "tskey-api-test123")
    monkeypatch.setenv("TAILSCALE_WRITE_ENABLED", "true")


@pytest.fixture()
def sample_devices() -> list[dict[str, Any]]:
    """Sample device list response."""
    return [
        {
            "nodeId": "n1234567890",
            "id": "12345",
            "name": "macbook.tail12345.ts.net",
            "hostname": "macbook",
            "os": "macOS 15.3",
            "addresses": ["100.100.1.1", "fd7a:115c:a1e0::1"],
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
            "user": "user@example.com",
        },
        {
            "nodeId": "n9876543210",
            "id": "67890",
            "name": "nas.tail12345.ts.net",
            "hostname": "nas",
            "os": "Linux 6.8",
            "addresses": ["100.100.1.2"],
            "clientVersion": "1.74.0",
            "updateAvailable": True,
            "created": "2024-06-01T08:00:00Z",
            "lastSeen": "2026-04-10T06:00:00Z",
            "connectedToControl": True,
            "authorized": True,
            "isExternal": False,
            "isEphemeral": False,
            "keyExpiryDisabled": True,
            "expires": "2099-01-01T00:00:00Z",
            "tags": ["tag:server", "tag:infra"],
            "user": "user@example.com",
        },
        {
            "nodeId": "n5555555555",
            "id": "55555",
            "name": "phone.tail12345.ts.net",
            "hostname": "phone",
            "os": "iOS 18.4",
            "addresses": ["100.100.1.3"],
            "clientVersion": "1.76.0",
            "updateAvailable": False,
            "created": "2025-06-01T12:00:00Z",
            "lastSeen": "2026-04-09T18:00:00Z",
            "connectedToControl": False,
            "authorized": True,
            "isExternal": False,
            "isEphemeral": False,
            "keyExpiryDisabled": False,
            "expires": "2026-05-01T12:00:00Z",
            "tags": [],
            "user": "user@example.com",
        },
    ]


@pytest.fixture()
def sample_settings() -> dict[str, Any]:
    """Sample tailnet settings response."""
    return {
        "devicesApprovalOn": False,
        "devicesAutoUpdatesOn": True,
        "devicesKeyDurationDays": 180,
        "usersApprovalOn": False,
        "networkFlowLoggingOn": True,
        "regionalRoutingOn": True,
        "postureIdentityCollectionOn": False,
        "httpsEnabled": True,
    }


@pytest.fixture()
def sample_users() -> list[dict[str, Any]]:
    """Sample users list response."""
    return [
        {
            "id": "u1",
            "displayName": "Alice",
            "loginName": "alice@example.com",
            "role": "owner",
            "status": "active",
            "deviceCount": 3,
            "currentlyConnected": True,
            "lastSeen": "2026-04-11T12:00:00Z",
        },
        {
            "id": "u2",
            "displayName": "Bob",
            "loginName": "bob@example.com",
            "role": "member",
            "status": "active",
            "deviceCount": 1,
            "currentlyConnected": False,
            "lastSeen": "2026-04-10T08:00:00Z",
        },
    ]


@pytest.fixture()
def sample_keys() -> list[dict[str, Any]]:
    """Sample auth keys list response."""
    return [
        {
            "id": "k1234",
            "description": "CI/CD key",
            "capabilities": {
                "devices": {
                    "create": {
                        "reusable": True,
                        "ephemeral": True,
                        "preauthorized": True,
                        "tags": ["tag:ci"],
                    }
                }
            },
            "revoked": False,
            "expires": "2026-06-01T00:00:00Z",
        },
        {
            "id": "k5678",
            "description": "One-time server key",
            "capabilities": {
                "devices": {
                    "create": {
                        "reusable": False,
                        "ephemeral": False,
                        "preauthorized": True,
                    }
                }
            },
            "revoked": False,
            "expires": "2026-04-15T00:00:00Z",
        },
    ]


@pytest.fixture()
def sample_dns() -> dict[str, Any]:
    """Sample DNS configuration."""
    return {
        "nameservers": ["100.100.100.100", "1.1.1.1"],
        "magic_dns": True,
        "search_paths": ["tail12345.ts.net"],
        "split_dns": {
            "internal.corp": ["10.0.0.1", "10.0.0.2"],
        },
    }


@pytest.fixture()
def sample_acl() -> dict[str, Any]:
    """Sample ACL policy."""
    return {
        "groups": {
            "group:admin": ["alice@example.com"],
            "group:infra": ["alice@example.com", "bob@example.com"],
        },
        "acls": [
            {"action": "accept", "src": ["group:admin"], "dst": ["*:*"]},
            {"action": "accept", "src": ["group:infra"], "dst": ["tag:server:22,443"]},
            {"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]},
        ],
        "ssh": [
            {"action": "accept", "src": ["group:admin"], "dst": ["tag:server"], "users": ["root", "autogroup:nonroot"]},
        ],
        "tagOwners": {
            "tag:server": ["group:admin"],
            "tag:infra": ["group:admin"],
            "tag:ci": ["group:infra"],
        },
    }


@pytest.fixture()
def sample_webhooks() -> list[dict[str, Any]]:
    """Sample webhooks list response."""
    return [
        {
            "endpointId": "wh1",
            "endpointUrl": "https://hooks.example.com/tailscale",
            "subscriptions": ["nodeCreated", "nodeKeyExpired", "policyUpdate"],
            "created": "2026-01-15T10:00:00Z",
        },
    ]


@pytest.fixture()
def sample_audit_log() -> list[dict[str, Any]]:
    """Sample audit log entries."""
    return [
        {
            "eventTime": "2026-04-11T10:00:00Z",
            "type": "PolicyFileUpdated",
            "actor": {"displayName": "Alice", "loginName": "alice@example.com"},
            "target": {"name": "ACL policy"},
        },
        {
            "eventTime": "2026-04-10T14:00:00Z",
            "type": "DeviceAuthorized",
            "actor": {"displayName": "Bob", "loginName": "bob@example.com"},
            "target": {"name": "phone", "id": "55555"},
        },
    ]
