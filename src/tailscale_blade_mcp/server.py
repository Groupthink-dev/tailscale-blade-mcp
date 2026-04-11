"""Tailscale Blade MCP Server — network monitoring and security for Tailscale tailnets.

Wraps the Tailscale REST API v2 as MCP tools. Token-efficient by default:
compact output, null-field omission, one line per item.
"""

from __future__ import annotations

import logging
import os
from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from tailscale_blade_mcp.client import TailscaleClient, TailscaleError
from tailscale_blade_mcp.formatters import (
    format_acl,
    format_acl_validation,
    format_audit_log,
    format_device_detail,
    format_device_list,
    format_device_routes,
    format_dns,
    format_info,
    format_key_list,
    format_user_list,
    format_webhook_list,
)
from tailscale_blade_mcp.models import require_write

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

log_level = os.environ.get("TAILSCALE_LOG_LEVEL", "WARNING").upper()
logging.basicConfig(level=getattr(logging, log_level, logging.WARNING))

# ---------------------------------------------------------------------------
# Transport configuration
# ---------------------------------------------------------------------------

TRANSPORT = os.environ.get("TAILSCALE_MCP_TRANSPORT", "stdio")
HTTP_HOST = os.environ.get("TAILSCALE_MCP_HOST", "127.0.0.1")
HTTP_PORT = int(os.environ.get("TAILSCALE_MCP_PORT", "8782"))

# ---------------------------------------------------------------------------
# FastMCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "TailscaleBlade",
    instructions=(
        "Tailscale network operations. Monitor devices, inspect ACL policies, "
        "check DNS configuration, audit auth keys and users. "
        "Write operations (authorize, tag, expire, delete) require TAILSCALE_WRITE_ENABLED=true."
    ),
)

# Lazy-initialized client
_client: TailscaleClient | None = None


def _get_client() -> TailscaleClient:
    """Get or create the TailscaleClient singleton."""
    global _client  # noqa: PLW0603
    if _client is None:
        _client = TailscaleClient()
    return _client


def _error_response(e: TailscaleError) -> str:
    """Format a client error as a user-friendly string."""
    return f"Error: {e}"


# ===========================================================================
# INFO
# ===========================================================================


@mcp.tool()
async def ts_info() -> str:
    """Health check: device counts, online/offline, key expiry warnings, updates, tailnet settings, write gate."""
    try:
        client = _get_client()
        settings = await client.get_settings()
        devices = await client.get_devices()
        users = await client.get_users()
        return format_info(settings, devices, users)
    except TailscaleError as e:
        return _error_response(e)


# ===========================================================================
# DEVICES
# ===========================================================================


@mcp.tool()
async def ts_devices() -> str:
    """List all devices: hostname, OS, IP, online/offline, key expiry, tags, update status."""
    try:
        devices = await _get_client().get_devices()
        return format_device_list(devices)
    except TailscaleError as e:
        return _error_response(e)


@mcp.tool()
async def ts_device(
    device_id: Annotated[str, Field(description="Device nodeId (from ts_devices)")],
) -> str:
    """Full detail for a single device: addresses, OS, client version, key status, tags, user."""
    try:
        device = await _get_client().get_device(device_id)
        return format_device_detail(device)
    except TailscaleError as e:
        return _error_response(e)


@mcp.tool()
async def ts_device_routes(
    device_id: Annotated[str, Field(description="Device nodeId (from ts_devices)")],
) -> str:
    """Routes for a device: advertised subnets, approved/unapproved status."""
    try:
        routes = await _get_client().get_device_routes(device_id)
        return format_device_routes(routes)
    except TailscaleError as e:
        return _error_response(e)


# ===========================================================================
# DNS
# ===========================================================================


@mcp.tool()
async def ts_dns() -> str:
    """DNS configuration: nameservers, MagicDNS status, search paths, split DNS rules."""
    try:
        dns = await _get_client().get_dns()
        return format_dns(dns)
    except TailscaleError as e:
        return _error_response(e)


# ===========================================================================
# ACL / POLICY
# ===========================================================================


@mcp.tool()
async def ts_acl() -> str:
    """ACL policy summary: groups, rules, SSH rules, tag owners. Shows who can talk to whom."""
    try:
        acl = await _get_client().get_acl()
        return format_acl(acl)
    except TailscaleError as e:
        return _error_response(e)


@mcp.tool()
async def ts_acl_validate(
    policy_json: Annotated[str, Field(description="ACL policy as JSON string to validate")],
) -> str:
    """Validate an ACL policy without applying it. Returns errors or 'passed'."""
    import json

    gate = require_write()
    if gate:
        return gate
    try:
        policy = json.loads(policy_json)
        result = await _get_client().validate_acl(policy)
        return format_acl_validation(result)
    except json.JSONDecodeError as e:
        return f"Error: Invalid JSON: {e}"
    except TailscaleError as e:
        return _error_response(e)


# ===========================================================================
# KEYS
# ===========================================================================


@mcp.tool()
async def ts_keys() -> str:
    """List auth keys: ID, description, reusable/ephemeral/preauth flags, tags, expiry."""
    try:
        keys = await _get_client().get_keys()
        return format_key_list(keys)
    except TailscaleError as e:
        return _error_response(e)


# ===========================================================================
# USERS
# ===========================================================================


@mcp.tool()
async def ts_users() -> str:
    """List users: name, login, role, status, device count, online/last seen."""
    try:
        users = await _get_client().get_users()
        return format_user_list(users)
    except TailscaleError as e:
        return _error_response(e)


# ===========================================================================
# WEBHOOKS
# ===========================================================================


@mcp.tool()
async def ts_webhooks() -> str:
    """List configured webhooks: endpoint URL, event subscriptions, created date."""
    try:
        webhooks = await _get_client().get_webhooks()
        return format_webhook_list(webhooks)
    except TailscaleError as e:
        return _error_response(e)


# ===========================================================================
# AUDIT LOG
# ===========================================================================


@mcp.tool()
async def ts_audit_log(
    count: Annotated[int, Field(description="Number of entries to return (default 50)", ge=1, le=200)] = 50,
) -> str:
    """Configuration audit log: who changed what, when. Recent entries first."""
    try:
        entries = await _get_client().get_audit_log(count)
        return format_audit_log(entries)
    except TailscaleError as e:
        return _error_response(e)


# ===========================================================================
# WRITE OPERATIONS (gated by TAILSCALE_WRITE_ENABLED=true)
# ===========================================================================


@mcp.tool()
async def ts_authorize_device(
    device_id: Annotated[str, Field(description="Device nodeId (from ts_devices)")],
    authorized: Annotated[bool, Field(description="True to authorize, false to deauthorize")] = True,
) -> str:
    """Authorize or deauthorize a device. Requires TAILSCALE_WRITE_ENABLED=true."""
    gate = require_write()
    if gate:
        return gate
    try:
        await _get_client().authorize_device(device_id, authorized)
        action = "Authorized" if authorized else "Deauthorized"
        return f"{action} device {device_id}"
    except TailscaleError as e:
        return _error_response(e)


@mcp.tool()
async def ts_set_tags(
    device_id: Annotated[str, Field(description="Device nodeId (from ts_devices)")],
    tags: Annotated[list[str], Field(description="ACL tags to set (e.g. ['tag:server', 'tag:prod'])")],
) -> str:
    """Set ACL tags on a device. Replaces existing tags. Requires TAILSCALE_WRITE_ENABLED=true."""
    gate = require_write()
    if gate:
        return gate
    try:
        await _get_client().set_device_tags(device_id, tags)
        return f"Set tags on {device_id}: {', '.join(tags)}"
    except TailscaleError as e:
        return _error_response(e)


@mcp.tool()
async def ts_expire_device(
    device_id: Annotated[str, Field(description="Device nodeId (from ts_devices)")],
) -> str:
    """Force key expiry on a device — it must re-authenticate. Requires TAILSCALE_WRITE_ENABLED=true."""
    gate = require_write()
    if gate:
        return gate
    try:
        await _get_client().expire_device(device_id)
        return f"Expired key for device {device_id}"
    except TailscaleError as e:
        return _error_response(e)


@mcp.tool()
async def ts_approve_routes(
    device_id: Annotated[str, Field(description="Device nodeId (from ts_devices)")],
    routes: Annotated[list[str], Field(description="Subnet routes to approve (e.g. ['192.168.1.0/24'])")],
) -> str:
    """Approve subnet routes on a device. Requires TAILSCALE_WRITE_ENABLED=true."""
    gate = require_write()
    if gate:
        return gate
    try:
        await _get_client().set_device_routes(device_id, routes)
        return f"Set routes on {device_id}: {', '.join(routes)}"
    except TailscaleError as e:
        return _error_response(e)


@mcp.tool()
async def ts_create_key(
    description: Annotated[str, Field(description="Description for the auth key")] = "",
    reusable: Annotated[bool, Field(description="Allow key to be used multiple times")] = False,
    ephemeral: Annotated[bool, Field(description="Devices using this key are ephemeral (auto-removed)")] = False,
    preauthorized: Annotated[bool, Field(description="Devices are pre-approved (no manual auth needed)")] = False,
    tags: Annotated[list[str] | None, Field(description="ACL tags for devices using this key")] = None,
    expiry_seconds: Annotated[int, Field(description="Key lifetime in seconds (default 86400 = 24h)")] = 86400,
) -> str:
    """Create a new auth key. Requires TAILSCALE_WRITE_ENABLED=true."""
    gate = require_write()
    if gate:
        return gate
    try:
        result = await _get_client().create_key(
            reusable=reusable,
            ephemeral=ephemeral,
            preauthorized=preauthorized,
            tags=tags,
            expiry_seconds=expiry_seconds,
            description=description,
        )
        key_id = result.get("id", "?")
        key_value = result.get("key", "")
        lines = [f"Created auth key: {key_id}"]
        if key_value:
            lines.append(f"Key: {key_value}")
            lines.append("(save this — it won't be shown again)")
        return "\n".join(lines)
    except TailscaleError as e:
        return _error_response(e)


@mcp.tool()
async def ts_delete_key(
    key_id: Annotated[str, Field(description="Auth key ID to revoke (from ts_keys)")],
    confirm: Annotated[bool, Field(description="Must be true to confirm — revokes the key permanently")] = False,
) -> str:
    """Revoke an auth key. Requires TAILSCALE_WRITE_ENABLED=true and confirm=true."""
    gate = require_write()
    if gate:
        return gate
    if not confirm:
        return "Error: Set confirm=true to revoke this key."
    try:
        await _get_client().delete_key(key_id)
        return f"Revoked auth key {key_id}"
    except TailscaleError as e:
        return _error_response(e)


@mcp.tool()
async def ts_delete_device(
    device_id: Annotated[str, Field(description="Device nodeId (from ts_devices)")],
    confirm: Annotated[bool, Field(description="Must be true to confirm — removes device from tailnet")] = False,
) -> str:
    """Delete a device from the tailnet. Requires TAILSCALE_WRITE_ENABLED=true and confirm=true."""
    gate = require_write()
    if gate:
        return gate
    if not confirm:
        return "Error: Set confirm=true to delete this device."
    try:
        await _get_client().delete_device(device_id)
        return f"Deleted device {device_id}"
    except TailscaleError as e:
        return _error_response(e)


# ===========================================================================
# Entry point
# ===========================================================================


def main() -> None:
    """Run the MCP server."""
    if TRANSPORT == "http":
        import uvicorn

        from tailscale_blade_mcp.auth import BearerAuthMiddleware

        app = mcp.http_app()
        app.add_middleware(BearerAuthMiddleware)
        uvicorn.run(app, host=HTTP_HOST, port=HTTP_PORT)
    else:
        mcp.run(transport="stdio")
