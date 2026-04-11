"""Tailscale API client wrapper.

Wraps the Tailscale REST API v2 with credential scrubbing, structured error
handling, and typed convenience methods. All methods are async via httpx.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from tailscale_blade_mcp.models import TailscaleConfig, parse_config

logger = logging.getLogger(__name__)

# Patterns to scrub from error messages
_CREDENTIAL_PATTERNS = [
    re.compile(r"tskey-[a-zA-Z0-9\-]+", re.IGNORECASE),
    re.compile(r"Bearer\s+\S+", re.IGNORECASE),
    re.compile(r"Authorization[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"token[=:]\S+", re.IGNORECASE),
]


class TailscaleError(Exception):
    """Base error for Tailscale client operations."""


class AuthError(TailscaleError):
    """Authentication failed."""


class NotFoundError(TailscaleError):
    """Requested resource not found."""


class RateLimitError(TailscaleError):
    """Rate limit exceeded."""


def _scrub(message: str) -> str:
    """Remove credentials from error messages."""
    for pattern in _CREDENTIAL_PATTERNS:
        message = pattern.sub("[REDACTED]", message)
    return message


class TailscaleClient:
    """Tailscale API client.

    Wraps the Tailscale REST API v2 with:
    - Async httpx client with Bearer auth
    - Credential scrubbing on all errors
    - Structured error handling (auth, not-found, rate-limit)
    - Tailnet "-" shorthand for auto-detection
    """

    def __init__(self) -> None:
        self._config = parse_config()
        self._http: httpx.AsyncClient | None = None

    @property
    def config(self) -> TailscaleConfig:
        """Return the current configuration."""
        return self._config

    def _get_http(self) -> httpx.AsyncClient:
        """Get or create the httpx client."""
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                base_url=self._config.api_base,
                headers={
                    "Authorization": f"Bearer {self._config.api_key}",
                    "Accept": "application/json",
                },
                timeout=30.0,
            )
        return self._http

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http and not self._http.is_closed:
            await self._http.aclose()
            self._http = None

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Make an API request with error handling and credential scrubbing."""
        http = self._get_http()
        try:
            resp = await http.request(method, path, **kwargs)
        except httpx.HTTPError as e:
            raise TailscaleError(_scrub(f"Request failed: {e}")) from e

        if resp.status_code == 401:
            raise AuthError("Authentication failed. Check your TAILSCALE_API_KEY.")
        if resp.status_code == 403:
            raise AuthError(_scrub(f"Forbidden: insufficient permissions for {method} {path}"))
        if resp.status_code == 404:
            raise NotFoundError(f"Not found: {path}")
        if resp.status_code == 429:
            raise RateLimitError("Rate limit exceeded. Try again later.")
        if resp.status_code >= 400:
            body = resp.text
            raise TailscaleError(_scrub(f"API error {resp.status_code}: {body}"))

        if resp.status_code == 204:
            return None
        return resp.json()

    def _tailnet_path(self, suffix: str) -> str:
        """Build a tailnet-scoped API path."""
        return f"/tailnet/{self._config.tailnet}/{suffix}"

    # ------------------------------------------------------------------
    # Tailnet Info & Settings
    # ------------------------------------------------------------------

    async def get_settings(self) -> dict[str, Any]:
        """Get tailnet settings."""
        data: dict[str, Any] = await self._request("GET", self._tailnet_path("settings"))
        return data

    # ------------------------------------------------------------------
    # Devices
    # ------------------------------------------------------------------

    async def get_devices(self) -> list[dict[str, Any]]:
        """Get all devices in the tailnet."""
        data: dict[str, Any] = await self._request("GET", self._tailnet_path("devices?fields=all"))
        result: list[dict[str, Any]] = data.get("devices", [])
        return result

    async def get_device(self, device_id: str) -> dict[str, Any]:
        """Get a single device by nodeId."""
        data: dict[str, Any] = await self._request("GET", f"/device/{device_id}?fields=all")
        return data

    async def get_device_routes(self, device_id: str) -> dict[str, Any]:
        """Get routes for a device."""
        data: dict[str, Any] = await self._request("GET", f"/device/{device_id}/routes")
        return data

    async def authorize_device(self, device_id: str, authorized: bool = True) -> None:
        """Authorize or deauthorize a device."""
        await self._request("POST", f"/device/{device_id}/authorized", json={"authorized": authorized})

    async def expire_device(self, device_id: str) -> None:
        """Force key expiry on a device."""
        await self._request("POST", f"/device/{device_id}/expire")

    async def set_device_tags(self, device_id: str, tags: list[str]) -> None:
        """Set ACL tags on a device."""
        await self._request("POST", f"/device/{device_id}/tags", json={"tags": tags})

    async def set_device_routes(self, device_id: str, routes: list[str]) -> None:
        """Set (approve) routes on a device."""
        await self._request("POST", f"/device/{device_id}/routes", json={"routes": routes})

    async def delete_device(self, device_id: str) -> None:
        """Delete a device from the tailnet."""
        await self._request("DELETE", f"/device/{device_id}")

    # ------------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------------

    async def get_dns(self) -> dict[str, Any]:
        """Get full DNS configuration (nameservers, search paths, MagicDNS, split DNS)."""
        nameservers: dict[str, Any] = await self._request("GET", self._tailnet_path("dns/nameservers"))
        preferences: dict[str, Any] = await self._request("GET", self._tailnet_path("dns/preferences"))
        searchpaths: dict[str, Any] = await self._request("GET", self._tailnet_path("dns/searchpaths"))
        split_dns: dict[str, Any] = await self._request("GET", self._tailnet_path("dns/split-dns"))
        return {
            "nameservers": nameservers.get("dns", []),
            "magic_dns": preferences.get("magicDNSEnabled", False),
            "search_paths": searchpaths.get("searchPaths", []),
            "split_dns": split_dns,
        }

    # ------------------------------------------------------------------
    # ACL / Policy
    # ------------------------------------------------------------------

    async def get_acl(self) -> dict[str, Any]:
        """Get the ACL policy file."""
        data: dict[str, Any] = await self._request("GET", self._tailnet_path("acl"))
        return data

    async def validate_acl(self, policy: dict[str, Any]) -> dict[str, Any]:
        """Validate an ACL policy file."""
        data: dict[str, Any] = await self._request("POST", self._tailnet_path("acl/validate"), json=policy)
        return data

    # ------------------------------------------------------------------
    # Keys
    # ------------------------------------------------------------------

    async def get_keys(self) -> list[dict[str, Any]]:
        """List auth keys."""
        data: dict[str, Any] = await self._request("GET", self._tailnet_path("keys"))
        result: list[dict[str, Any]] = data.get("keys", [])
        return result

    async def create_key(
        self,
        *,
        reusable: bool = False,
        ephemeral: bool = False,
        preauthorized: bool = False,
        tags: list[str] | None = None,
        expiry_seconds: int = 86400,
        description: str = "",
    ) -> dict[str, Any]:
        """Create an auth key."""
        capabilities: dict[str, Any] = {
            "devices": {
                "create": {
                    "reusable": reusable,
                    "ephemeral": ephemeral,
                    "preauthorized": preauthorized,
                }
            }
        }
        if tags:
            capabilities["devices"]["create"]["tags"] = tags

        body: dict[str, Any] = {
            "capabilities": capabilities,
            "expirySeconds": expiry_seconds,
        }
        if description:
            body["description"] = description

        data: dict[str, Any] = await self._request("POST", self._tailnet_path("keys"), json=body)
        return data

    async def delete_key(self, key_id: str) -> None:
        """Delete/revoke an auth key."""
        await self._request("DELETE", self._tailnet_path(f"keys/{key_id}"))

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    async def get_users(self) -> list[dict[str, Any]]:
        """List users in the tailnet."""
        data: dict[str, Any] = await self._request("GET", self._tailnet_path("users"))
        result: list[dict[str, Any]] = data.get("users", [])
        return result

    # ------------------------------------------------------------------
    # Webhooks
    # ------------------------------------------------------------------

    async def get_webhooks(self) -> list[dict[str, Any]]:
        """List webhooks."""
        data: dict[str, Any] = await self._request("GET", self._tailnet_path("webhooks"))
        result: list[dict[str, Any]] = data.get("webhooks", [])
        return result

    # ------------------------------------------------------------------
    # Audit Logs
    # ------------------------------------------------------------------

    async def get_audit_log(self, count: int = 50) -> list[dict[str, Any]]:
        """Get configuration audit log entries."""
        data: dict[str, Any] = await self._request("GET", self._tailnet_path(f"logging/configuration?count={count}"))
        result: list[dict[str, Any]] = data.get("logs", [])
        return result
