"""Tailscale Blade MCP Server — network monitoring and security for Tailscale tailnets.

Wraps the Tailscale REST API v2 as MCP tools. Token-efficient by default:
compact output, null-field omission, one line per item.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Annotated, Any

from fastmcp import FastMCP
from pydantic import Field

from tailscale_blade_mcp.client import TailscaleClient, TailscaleError
from tailscale_blade_mcp.domain_hint import (
    Pattern,
    compute_domain_hint,
    load_patterns_from_yaml,
)
from tailscale_blade_mcp.formatters import (
    append_meta_envelope,
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
from tailscale_blade_mcp.models import (
    apply_scope_filter,
    parse_scope_tag_map,
    require_write,
    validate_scope,
)

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


def _build_filtered_by(
    scope: str | None,
    scope_tag_list: list[str],
    extra: dict[str, Any] | None = None,
) -> list[str]:
    """Construct the _meta envelope's filtered_by list.

    Always emits the entries in a stable order:
      1. scope=<value> (if scope was provided)
      2. tags=<comma-joined sorted list> (if scope filter applied)
      3. extra entries (e.g. device_id=…, count=…) in insertion order.

    Empty list when scope is None and no extras — assembler still receives
    an envelope (audit-surface uniformity per spec) but with no filter
    facets recorded.
    """
    parts: list[str] = []
    if scope is not None:
        parts.append(f"scope={scope}")
        if scope_tag_list:
            parts.append(f"tags={','.join(scope_tag_list)}")
    if extra:
        for k, v in extra.items():
            parts.append(f"{k}={v}")
    return parts


# ---------------------------------------------------------------------------
# DD-338 A.2.dom.c — BladeConfigStore reader + Tailscale field projector
# ---------------------------------------------------------------------------

_BLADE_ID = "tailscale-blade-mcp"


def _state_root() -> str:
    """Resolve Stallari state root.

    Honours ``STALLARI_STATE_ROOT`` env var (used in tests + non-standard
    deployments); falls back to the macOS Application Support default per
    Convention #27 / StallariPaths.
    """
    override = os.environ.get("STALLARI_STATE_ROOT")
    if override:
        return override
    return os.path.expanduser("~/Library/Application Support/Stallari")


def _sanitize_blade_id(blade_id: str) -> str:
    """Mirror the Swift writer's blade-id directory naming.

    Lower-case + ``/`` ⇒ ``_`` — kept in lockstep with BladeConfigStore.swift
    (Convention #23: reader and writer agree on the on-disk shape).
    """
    return blade_id.lower().replace("/", "_")


def _load_blade_config(blade_id: str) -> list[Pattern]:
    """Read this blade's domain_hint patterns from the BladeConfigStore.

    Convention #22 graceful degradation: missing / unreadable / malformed
    config returns ``[]`` — the blade still runs, simply without per-record
    ``domain_hints`` emission.

    Convention #23 reader-side compliance: resolves via state-root +
    ``blade-config/<sanitized-blade>/config.yaml`` in lockstep with the
    Swift writer's path layout.
    """
    config_path = os.path.join(
        _state_root(),
        "blade-config",
        _sanitize_blade_id(blade_id),
        "config.yaml",
    )
    try:
        with open(config_path, encoding="utf-8") as f:
            yaml_str = f.read()
    except OSError:
        return []
    return load_patterns_from_yaml(yaml_str)


# Cached at module load; re-launch the blade to pick up config edits at v1.
_PATTERNS: list[Pattern] = _load_blade_config(_BLADE_ID)


def _tailscale_field_projector(record: dict[str, Any], field: str) -> Any:
    """Project a Tailscale record onto a logical ``Pattern.field`` name.

    Tailscale Devices API record shape (subset)::

        {
          "id": "12345",
          "nodeId": "n...",
          "name": "host.tailnet.ts.net",
          "hostname": "host",
          "addresses": ["100.x.y.z"],
          "user": "user@example.com",
          "tags": ["tag:server", "tag:prod"],
          "os": "linux",
          ...
        }

    Supported field names (case-insensitive): ``hostname``, ``name``,
    ``tags`` (list), ``user``, ``addresses`` (list), ``os``. Auth-key
    records expose top-level ``tags`` (post-flatten); user records expose
    ``loginName`` mapped from ``user`` and ``displayName`` as scalar; audit
    entries expose ``actor`` / ``target.id`` shapes (best-effort projector
    falls back to ``None`` for unknown field names so dispatch silently
    skips the rule instead of crashing).
    """
    if not isinstance(record, dict):
        return None
    f = field.lower()
    if f == "hostname":
        return record.get("hostname")
    if f == "name":
        return record.get("name")
    if f == "tags":
        v = record.get("tags")
        return v if isinstance(v, list) else None
    if f == "user":
        # Device records: ``user`` is a login email string.
        # User records: ``loginName`` is the analogous field.
        return record.get("user") or record.get("loginName")
    if f == "addresses":
        v = record.get("addresses")
        return v if isinstance(v, list) else None
    if f == "os":
        return record.get("os")
    if f == "id":
        return record.get("nodeId") or record.get("id")
    return None


def _record_id(rec: dict[str, Any]) -> str | None:
    """Resolve the stable record ID for the ``domain_hints`` map key.

    Tailscale device records preferentially use ``nodeId`` (newer, stable);
    falls back to legacy ``id`` (auth-key records, user records, audit
    entries). Returns ``None`` for records without either — caller omits
    them from the hints map.
    """
    if not isinstance(rec, dict):
        return None
    for key in ("nodeId", "id"):
        v = rec.get(key)
        if isinstance(v, str) and v:
            return v
        if isinstance(v, int):
            return str(v)
    return None


def _compute_domain_hints_for_records(records: list[dict[str, Any]]) -> dict[str, str]:
    """Apply ``_PATTERNS`` to each record; return ``{record_id: domain}`` map.

    Records lacking a domain match are omitted. Empty pattern list ⇒ empty
    dict ⇒ caller suppresses the ``domain_hints`` envelope key.
    """
    if not _PATTERNS:
        return {}
    out: dict[str, str] = {}
    for rec in records:
        rid = _record_id(rec)
        if rid is None:
            continue
        hint = compute_domain_hint(rec, _PATTERNS, _tailscale_field_projector)
        if hint is not None:
            out[rid] = hint
    return out


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
async def ts_devices(
    scope: Annotated[
        str | None,
        Field(
            description=(
                "DD-278 scope filter: 'infrastructure' | 'personal' | 'home'. "
                "Filtered client-side after fetch (Tailscale REST API v2 has no "
                "server-side tag filter primitive). 'public' is unsupported."
            ),
        ),
    ] = None,
) -> str:
    """List all devices: hostname, OS, IP, online/offline, key expiry, tags, update status.

    Optional ``scope`` arg filters devices by DD-278 scope-tag mapping
    (configurable via TAILSCALE_SCOPE_{INFRASTRUCTURE,PERSONAL,HOME}_TAGS).
    Output includes a Track 3 ``_meta`` envelope as a JSON tail line.
    """
    started = time.monotonic()
    try:
        validate_scope(scope)
    except ValueError as ve:
        return f"Error: {ve}"
    try:
        devices = await _get_client().get_devices()
        # DD-338 B.1.b: canonical sort-before-return on nodeId asc (legacy `id` tie-break).
        # Sort BEFORE apply_scope_filter so post-filter output is order-preserving.
        devices = sorted(devices, key=lambda d: (d.get("nodeId", "") or "", d.get("id", "") or ""))
        matched_total = len(devices)
        filtered, scope_tag_list = apply_scope_filter(devices, scope)
        returned = len(filtered)
        redactions = matched_total - returned
        payload = format_device_list(filtered)
        latency_ms = int((time.monotonic() - started) * 1000)
        meta: dict[str, Any] = {
            "matched_total": matched_total,
            "returned": returned,
            "filtered_by": _build_filtered_by(scope, scope_tag_list),
            "redactions": redactions,
            "latency_ms": latency_ms,
        }
        domain_hints = _compute_domain_hints_for_records(filtered)
        if domain_hints:
            meta["domain_hints"] = domain_hints
        return append_meta_envelope(payload, meta)
    except TailscaleError as e:
        return _error_response(e)


@mcp.tool()
async def ts_device(
    device_id: Annotated[str, Field(description="Device nodeId (from ts_devices)")],
) -> str:
    """Full detail for a single device: addresses, OS, client version, key status, tags, user.

    Single-record fetch — server-side filter is ``device_id``-shaped, not
    tag-shaped. The ``_meta`` envelope is emitted for audit-surface
    uniformity; ``scope=`` is intentionally NOT accepted here because a
    scope filter on a single-device-detail call is semantically incoherent.
    """
    started = time.monotonic()
    try:
        device = await _get_client().get_device(device_id)
        payload = format_device_detail(device)
        latency_ms = int((time.monotonic() - started) * 1000)
        meta = {
            "matched_total": 1,
            "returned": 1,
            "filtered_by": _build_filtered_by(None, [], {"device_id": device_id}),
            "redactions": 0,
            "latency_ms": latency_ms,
        }
        return append_meta_envelope(payload, meta)
    except TailscaleError as e:
        return _error_response(e)


@mcp.tool()
async def ts_device_routes(
    device_id: Annotated[str, Field(description="Device nodeId (from ts_devices)")],
) -> str:
    """Routes for a device: advertised subnets, approved/unapproved status.

    Emits a DD-338 ``_meta`` envelope (``audit_surface: structured``) disclosing
    the ``device_id=`` server-side discrimination + the routes-row cardinality
    (advertised + enabled, union).
    """
    started = time.monotonic()
    try:
        routes = await _get_client().get_device_routes(device_id)
        payload = format_device_routes(routes)
        advertised = routes.get("advertisedRoutes", []) or []
        enabled = routes.get("enabledRoutes", []) or []
        # Union cardinality — discrete entries surfaced in the formatted payload.
        union_count = len(set(advertised) | set(enabled))
        latency_ms = int((time.monotonic() - started) * 1000)
        meta: dict[str, Any] = {
            "matched_total": union_count,
            "returned": union_count,
            "filtered_by": _build_filtered_by(None, [], {"device_id": device_id}),
            "redactions": 0,
            "latency_ms": latency_ms,
        }
        return append_meta_envelope(payload, meta)
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


def _flatten_key_tags(keys: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Surface each key's nested tag list at top-level ``tags`` for the filter.

    Tailscale keys carry tags at ``capabilities.devices.create.tags``; the
    generic ``apply_scope_filter`` helper keys off a top-level ``tags`` field
    by default. This helper returns a shallow-cloned list with the tag list
    hoisted; original key dicts are not mutated.
    """
    out: list[dict[str, Any]] = []
    for k in keys:
        clone = dict(k)
        nested = k.get("capabilities", {}).get("devices", {}).get("create", {}).get("tags", [])
        clone["tags"] = nested if isinstance(nested, list) else []
        out.append(clone)
    return out


@mcp.tool()
async def ts_keys(
    scope: Annotated[
        str | None,
        Field(
            description=(
                "DD-278 scope filter: 'infrastructure' | 'personal' | 'home'. "
                "Filtered client-side after fetch — matches the key's "
                "capabilities.devices.create.tags against the scope tag set."
            ),
        ),
    ] = None,
) -> str:
    """List auth keys: ID, description, reusable/ephemeral/preauth flags, tags, expiry.

    Optional ``scope`` arg filters keys by DD-278 scope-tag mapping. Output
    includes a Track 3 ``_meta`` envelope as a JSON tail line.
    """
    started = time.monotonic()
    try:
        validate_scope(scope)
    except ValueError as ve:
        return f"Error: {ve}"
    try:
        raw_keys = await _get_client().get_keys()
        keys_with_top_tags = _flatten_key_tags(raw_keys)
        # DD-338 B.1.b: canonical sort-before-return on key id asc.
        # Sort AFTER _flatten_key_tags (sees the hoisted-tag-clone shape) and
        # BEFORE apply_scope_filter (so post-filter output is order-preserving).
        keys_with_top_tags = sorted(keys_with_top_tags, key=lambda k: k.get("id", "") or "")
        matched_total = len(keys_with_top_tags)
        filtered, scope_tag_list = apply_scope_filter(keys_with_top_tags, scope)
        returned = len(filtered)
        redactions = matched_total - returned
        payload = format_key_list(filtered)
        latency_ms = int((time.monotonic() - started) * 1000)
        meta: dict[str, Any] = {
            "matched_total": matched_total,
            "returned": returned,
            "filtered_by": _build_filtered_by(scope, scope_tag_list),
            "redactions": redactions,
            "latency_ms": latency_ms,
        }
        domain_hints = _compute_domain_hints_for_records(filtered)
        if domain_hints:
            meta["domain_hints"] = domain_hints
        return append_meta_envelope(payload, meta)
    except TailscaleError as e:
        return _error_response(e)


# ===========================================================================
# USERS
# ===========================================================================


@mcp.tool()
async def ts_users() -> str:
    """List users: name, login, role, status, device count, online/last seen.
    Sorted by case-folded loginName ascending (numeric id tie-break)."""
    try:
        users = await _get_client().get_users()
        # DD-338 B.1.b: canonical sort-before-return on case-folded loginName
        # with numeric id tie-break. loginName is the stable user-mental-model
        # handle (email-shaped, unique within a tailnet); numeric id is opaque
        # to formatter output but provides deterministic tie-break.
        users = sorted(
            users,
            key=lambda u: (
                (u.get("loginName", "") or "").casefold(),
                str(u.get("id", "") or ""),
            ),
        )
        return format_user_list(users)
    except TailscaleError as e:
        return _error_response(e)


# ===========================================================================
# WEBHOOKS
# ===========================================================================


@mcp.tool()
async def ts_webhooks() -> str:
    """List configured webhooks: endpoint URL, event subscriptions, created date.
    Sorted by endpointId ascending."""
    try:
        webhooks = await _get_client().get_webhooks()
        # DD-338 B.1.b: canonical sort-before-return on endpointId ascending.
        webhooks = sorted(webhooks, key=lambda w: w.get("endpointId", "") or "")
        return format_webhook_list(webhooks)
    except TailscaleError as e:
        return _error_response(e)


# ===========================================================================
# AUDIT LOG
# ===========================================================================


@mcp.tool()
async def ts_audit_log(
    count: Annotated[int, Field(description="Number of entries to return (default 50)", ge=1, le=200)] = 50,
    scope: Annotated[
        str | None,
        Field(
            description=(
                "DD-278 scope filter: 'infrastructure' | 'personal' | 'home'. "
                "Filtered client-side — audit-log entries don't carry tags, so "
                "the filter resolves each entry's target.id against a "
                "secondary device-tag map fetch (one extra round-trip per call)."
            ),
        ),
    ] = None,
) -> str:
    """Configuration audit log: who changed what, when. Recent entries first.

    Optional ``scope`` arg filters audit entries to those whose ``target``
    is a device with a tag in the scope set. Requires a secondary fetch
    of the device-tag map (uncached at v1). Entries with non-device
    targets are excluded when ``scope`` is provided.
    """
    started = time.monotonic()
    try:
        validate_scope(scope)
    except ValueError as ve:
        return f"Error: {ve}"
    try:
        entries = await _get_client().get_audit_log(count)
        matched_total = len(entries)

        if scope is None:
            payload = format_audit_log(entries)
            latency_ms = int((time.monotonic() - started) * 1000)
            meta = {
                "matched_total": matched_total,
                "returned": matched_total,
                "filtered_by": _build_filtered_by(None, [], {"count": count}),
                "redactions": 0,
                "latency_ms": latency_ms,
            }
            return append_meta_envelope(payload, meta)

        # Secondary fetch: device-tag map keyed by both nodeId and legacy id.
        # An entry's target.id may be either; index by both to maximise hits.
        devices = await _get_client().get_devices()
        device_tag_map: dict[str, set[str]] = {}
        for d in devices:
            tags = set(d.get("tags") or [])
            for key in (d.get("nodeId"), d.get("id")):
                if key:
                    device_tag_map[str(key)] = tags

        scope_tag_map = parse_scope_tag_map()
        scope_tags = scope_tag_map.get(scope, set())

        filtered: list[dict[str, Any]] = []
        for entry in entries:
            target = entry.get("target") or {}
            target_id = target.get("id")
            target_type = target.get("type", "")
            # Restrict to device-target entries when scope filtering.
            if target_type and target_type.lower() != "node":
                continue
            if not target_id:
                continue
            entry_tags = device_tag_map.get(str(target_id), set())
            if scope == "personal":
                if not entry_tags or entry_tags & scope_tags:
                    filtered.append(entry)
            else:
                if entry_tags & scope_tags:
                    filtered.append(entry)

        returned = len(filtered)
        redactions = matched_total - returned
        payload = format_audit_log(filtered)
        latency_ms = int((time.monotonic() - started) * 1000)
        meta = {
            "matched_total": matched_total,
            "returned": returned,
            "filtered_by": _build_filtered_by(scope, sorted(scope_tags), {"count": count}),
            "redactions": redactions,
            "latency_ms": latency_ms,
        }
        return append_meta_envelope(payload, meta)
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
