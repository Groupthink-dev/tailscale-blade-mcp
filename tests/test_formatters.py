"""Tests for output formatters."""

from __future__ import annotations

from typing import Any

from tailscale_blade_mcp.formatters import (
    format_acl,
    format_acl_validation,
    format_audit_log,
    format_device_detail,
    format_device_line,
    format_device_list,
    format_device_routes,
    format_dns,
    format_info,
    format_key_line,
    format_key_list,
    format_user_line,
    format_user_list,
    format_webhook_list,
)


class TestDeviceFormatters:
    def test_device_line_online(self, sample_devices: list[dict[str, Any]]) -> None:
        line = format_device_line(sample_devices[0])
        assert "macbook" in line
        assert "mac" in line  # os=mac
        assert "100.100.1.1" in line
        assert "online" in line
        assert "n1234567890" in line

    def test_device_line_key_expiry_disabled(self, sample_devices: list[dict[str, Any]]) -> None:
        line = format_device_line(sample_devices[1])
        assert "nas" in line
        assert "KEY_EXPIRY_OFF" in line
        assert "server" in line  # tag
        assert "UPDATE_AVAILABLE" in line

    def test_device_line_offline(self, sample_devices: list[dict[str, Any]]) -> None:
        line = format_device_line(sample_devices[2])
        assert "phone" in line
        assert "OFFLINE" in line
        assert "iOS" in line

    def test_device_list_empty(self) -> None:
        assert format_device_list([]) == "(no devices)"

    def test_device_list(self, sample_devices: list[dict[str, Any]]) -> None:
        result = format_device_list(sample_devices)
        lines = result.strip().split("\n")
        assert len(lines) == 3

    def test_device_detail(self, sample_devices: list[dict[str, Any]]) -> None:
        result = format_device_detail(sample_devices[0])
        assert "macbook" in result
        assert "macOS 15.3" in result
        assert "1.76.1" in result
        assert "n1234567890" in result
        assert "100.100.1.1" in result
        assert "user@example.com" in result
        assert "yes" in result  # Authorized

    def test_device_detail_tags(self, sample_devices: list[dict[str, Any]]) -> None:
        result = format_device_detail(sample_devices[1])
        assert "tag:server" in result
        assert "tag:infra" in result
        assert "DISABLED" in result  # Key expiry disabled


class TestDeviceRouteFormatters:
    def test_routes_with_data(self) -> None:
        routes = {
            "advertisedRoutes": ["192.168.1.0/24", "10.0.0.0/8"],
            "enabledRoutes": ["192.168.1.0/24"],
        }
        result = format_device_routes(routes)
        assert "192.168.1.0/24" in result
        assert "enabled" in result
        assert "not approved" in result

    def test_routes_empty(self) -> None:
        routes = {"advertisedRoutes": [], "enabledRoutes": []}
        assert "(no routes)" in format_device_routes(routes)

    def test_routes_with_name(self) -> None:
        routes = {"advertisedRoutes": ["10.0.0.0/8"], "enabledRoutes": ["10.0.0.0/8"]}
        result = format_device_routes(routes, device_name="nas")
        assert "nas" in result


class TestDnsFormatters:
    def test_dns(self, sample_dns: dict[str, Any]) -> None:
        result = format_dns(sample_dns)
        assert "MagicDNS: enabled" in result
        assert "100.100.100.100" in result
        assert "1.1.1.1" in result
        assert "tail12345.ts.net" in result
        assert "internal.corp" in result
        assert "10.0.0.1" in result

    def test_dns_minimal(self) -> None:
        dns = {"nameservers": [], "magic_dns": False, "search_paths": [], "split_dns": {}}
        result = format_dns(dns)
        assert "MagicDNS: disabled" in result
        assert "(none)" in result


class TestAclFormatters:
    def test_acl(self, sample_acl: dict[str, Any]) -> None:
        result = format_acl(sample_acl)
        assert "Groups (2)" in result
        assert "group:admin" in result
        assert "ACL rules (3)" in result
        assert "accept" in result
        assert "SSH rules (1)" in result
        assert "Tag owners (3)" in result
        assert "tag:server" in result

    def test_acl_empty(self) -> None:
        assert "(empty policy)" in format_acl({})

    def test_acl_validation_passed(self) -> None:
        result = format_acl_validation({})
        assert "passed" in result

    def test_acl_validation_error(self) -> None:
        result = format_acl_validation({"message": "syntax error at line 5"})
        assert "syntax error" in result


class TestKeyFormatters:
    def test_key_line(self, sample_keys: list[dict[str, Any]]) -> None:
        line = format_key_line(sample_keys[0])
        assert "k1234" in line
        assert "CI/CD key" in line
        assert "reusable" in line
        assert "ephemeral" in line
        assert "preauth" in line
        assert "ci" in line  # tag

    def test_key_line_simple(self, sample_keys: list[dict[str, Any]]) -> None:
        line = format_key_line(sample_keys[1])
        assert "k5678" in line
        assert "preauth" in line
        assert "reusable" not in line

    def test_key_list_empty(self) -> None:
        assert format_key_list([]) == "(no auth keys)"

    def test_key_list(self, sample_keys: list[dict[str, Any]]) -> None:
        result = format_key_list(sample_keys)
        lines = result.strip().split("\n")
        assert len(lines) == 2


class TestUserFormatters:
    def test_user_line_online(self, sample_users: list[dict[str, Any]]) -> None:
        line = format_user_line(sample_users[0])
        assert "Alice" in line
        assert "alice@example.com" in line
        assert "owner" in line
        assert "devices=3" in line
        assert "online" in line

    def test_user_line_offline(self, sample_users: list[dict[str, Any]]) -> None:
        line = format_user_line(sample_users[1])
        assert "Bob" in line
        assert "member" in line
        assert "ago" in line  # last seen time

    def test_user_list_empty(self) -> None:
        assert format_user_list([]) == "(no users)"

    def test_user_list(self, sample_users: list[dict[str, Any]]) -> None:
        result = format_user_list(sample_users)
        lines = result.strip().split("\n")
        assert len(lines) == 2


class TestWebhookFormatters:
    def test_webhook_list(self, sample_webhooks: list[dict[str, Any]]) -> None:
        result = format_webhook_list(sample_webhooks)
        assert "wh1" in result
        assert "hooks.example.com" in result
        assert "events=3" in result

    def test_webhook_list_empty(self) -> None:
        assert format_webhook_list([]) == "(no webhooks)"


class TestAuditLogFormatters:
    def test_audit_log(self, sample_audit_log: list[dict[str, Any]]) -> None:
        result = format_audit_log(sample_audit_log)
        assert "2026-04-11" in result
        assert "Alice" in result
        assert "PolicyFileUpdated" in result
        assert "DeviceAuthorized" in result

    def test_audit_log_empty(self) -> None:
        assert format_audit_log([]) == "(no audit log entries)"


class TestInfoFormatter:
    def test_info(
        self,
        sample_settings: dict[str, Any],
        sample_devices: list[dict[str, Any]],
        sample_users: list[dict[str, Any]],
    ) -> None:
        result = format_info(sample_settings, sample_devices, sample_users)
        assert "Devices: 3 total" in result
        assert "2 online" in result
        assert "1 offline" in result
        assert "key expiry disabled" in result
        assert "update(s) available" in result
        assert "Users: 2" in result
        assert "auto-updates" in result
        assert "flow-logging" in result
        assert "key-ttl=180d" in result
        assert "Write enabled:" in result
