"""Token-efficient output formatters for Tailscale data.

Pipe-delimited, null-field omission, human-readable units.
One line per item for list views, structured blocks for detail views.
"""

from __future__ import annotations

from typing import Any


def _time_ago(iso_str: str | None) -> str:
    """Convert ISO timestamp to human-readable relative time."""
    if not iso_str:
        return "?"
    try:
        from datetime import UTC, datetime

        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        delta = datetime.now(UTC) - dt
        seconds = int(delta.total_seconds())
        if seconds < 0:
            return "future"
        if seconds < 60:
            return f"{seconds}s ago"
        if seconds < 3600:
            return f"{seconds // 60}m ago"
        if seconds < 86400:
            return f"{seconds // 3600}h ago"
        return f"{seconds // 86400}d ago"
    except (ValueError, TypeError):
        return "?"


def _short_date(iso_str: str | None) -> str:
    """Extract YYYY-MM-DD from an ISO timestamp."""
    if not iso_str:
        return "?"
    return iso_str[:10] if len(iso_str) >= 10 else iso_str


def _os_short(os_name: str | None) -> str:
    """Shorten OS names for compact output."""
    if not os_name:
        return "?"
    # Common shortenings
    for long, short in [
        ("Windows", "win"),
        ("macOS", "mac"),
        ("Linux", "linux"),
        ("iOS", "iOS"),
        ("Android", "android"),
        ("tvOS", "tvOS"),
    ]:
        if long.lower() in os_name.lower():
            return short
    return os_name[:12]


# ---------------------------------------------------------------------------
# Info / Settings
# ---------------------------------------------------------------------------


def format_info(settings: dict[str, Any], devices: list[dict[str, Any]], users: list[dict[str, Any]]) -> str:
    """Format tailnet health check."""
    lines = []

    # Device summary
    total = len(devices)
    online = sum(1 for d in devices if d.get("connectedToControl"))
    expired_keys = sum(1 for d in devices if _is_key_expired(d))
    no_expiry = sum(1 for d in devices if d.get("keyExpiryDisabled"))
    updates = sum(1 for d in devices if d.get("updateAvailable"))

    lines.append(f"Devices: {total} total | {online} online | {total - online} offline")
    if expired_keys:
        lines.append(f"⚠ {expired_keys} device(s) with expired keys")
    if no_expiry:
        lines.append(f"⚠ {no_expiry} device(s) with key expiry disabled")
    if updates:
        lines.append(f"↑ {updates} update(s) available")

    # User summary
    lines.append(f"Users: {len(users)}")

    # Settings
    s = settings
    flags = []
    if s.get("devicesApprovalOn"):
        flags.append("device-approval")
    if s.get("devicesAutoUpdatesOn"):
        flags.append("auto-updates")
    if s.get("networkFlowLoggingOn"):
        flags.append("flow-logging")
    if s.get("postureIdentityCollectionOn"):
        flags.append("posture")
    if s.get("httpsEnabled"):
        flags.append("https")
    key_days = s.get("devicesKeyDurationDays")
    if key_days:
        flags.append(f"key-ttl={key_days}d")

    if flags:
        lines.append(f"Settings: {' | '.join(flags)}")

    from tailscale_blade_mcp.models import is_write_enabled

    lines.append(f"Write enabled: {is_write_enabled()}")

    return "\n".join(lines)


def _is_key_expired(device: dict[str, Any]) -> bool:
    """Check if a device's key is expired."""
    expires = device.get("expires")
    if not expires:
        return False
    try:
        from datetime import UTC, datetime

        dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
        return dt < datetime.now(UTC)
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------------


def format_device_line(device: dict[str, Any]) -> str:
    """Format a single device as a compact pipe-delimited line."""
    parts = []

    name = device.get("name", "") or device.get("hostname", "") or "?"
    # Strip tailnet suffix from FQDN
    if "." in name:
        name = name.split(".")[0]
    parts.append(name)

    os_name = _os_short(device.get("os"))
    parts.append(f"os={os_name}")

    addresses = device.get("addresses", [])
    if addresses:
        parts.append(f"ip={addresses[0]}")

    if device.get("connectedToControl"):
        parts.append("online")
    else:
        parts.append("OFFLINE")
        parts.append(f"last={_time_ago(device.get('lastSeen'))}")

    if device.get("keyExpiryDisabled"):
        parts.append("KEY_EXPIRY_OFF")
    elif _is_key_expired(device):
        parts.append("KEY_EXPIRED")
    else:
        exp = device.get("expires")
        if exp:
            parts.append(f"expires={_short_date(exp)}")

    if device.get("updateAvailable"):
        parts.append("UPDATE_AVAILABLE")

    tags = device.get("tags", [])
    if tags:
        tag_str = ",".join(t.replace("tag:", "") for t in tags[:5])
        parts.append(f"tags={tag_str}")

    if not device.get("authorized"):
        parts.append("UNAUTHORIZED")

    if device.get("isExternal"):
        parts.append("external")

    node_id = device.get("nodeId", "")
    if node_id:
        parts.append(f"id={node_id}")

    return " | ".join(parts)


def format_device_list(devices: list[dict[str, Any]]) -> str:
    """Format a list of devices."""
    if not devices:
        return "(no devices)"
    return "\n".join(format_device_line(d) for d in devices)


def format_device_detail(device: dict[str, Any]) -> str:
    """Format detailed single-device view."""
    lines = []

    name = device.get("name", "") or device.get("hostname", "") or "?"
    lines.append(f"# {name}")
    lines.append("")

    node_id = device.get("nodeId", "")
    if node_id:
        lines.append(f"Node ID: {node_id}")
    lines.append(f"OS: {device.get('os', '?')}")
    lines.append(f"Client: {device.get('clientVersion', '?')}")
    lines.append(f"Created: {_short_date(device.get('created'))}")
    lines.append(f"Last seen: {_time_ago(device.get('lastSeen'))}")
    lines.append(f"Online: {'yes' if device.get('connectedToControl') else 'no'}")
    lines.append(f"Authorized: {'yes' if device.get('authorized') else 'NO'}")

    addresses = device.get("addresses", [])
    if addresses:
        lines.append(f"Addresses: {', '.join(addresses)}")

    # Key status
    if device.get("keyExpiryDisabled"):
        lines.append("Key expiry: DISABLED")
    elif _is_key_expired(device):
        lines.append(f"Key expiry: EXPIRED ({_short_date(device.get('expires'))})")
    else:
        lines.append(f"Key expires: {_short_date(device.get('expires'))}")

    if device.get("updateAvailable"):
        lines.append("Update: AVAILABLE")

    tags = device.get("tags", [])
    if tags:
        lines.append(f"Tags: {', '.join(tags)}")

    if device.get("isExternal"):
        lines.append("External: yes")
    if device.get("isEphemeral"):
        lines.append("Ephemeral: yes")
    if device.get("blocksIncomingConnections"):
        lines.append("Blocks incoming: yes")

    user = device.get("user", "")
    if user:
        lines.append(f"User: {user}")

    return "\n".join(lines)


def format_device_routes(routes: dict[str, Any], device_name: str = "") -> str:
    """Format device routes."""
    advertised = routes.get("advertisedRoutes", [])
    enabled = routes.get("enabledRoutes", [])

    if not advertised and not enabled:
        prefix = f"{device_name}: " if device_name else ""
        return f"{prefix}(no routes)"

    lines = []
    if device_name:
        lines.append(f"# Routes for {device_name}")
        lines.append("")

    if advertised:
        lines.append("Advertised:")
        for r in advertised:
            status = "✓ enabled" if r in enabled else "✗ not approved"
            lines.append(f"  {r} [{status}]")

    enabled_only = [r for r in enabled if r not in advertised]
    if enabled_only:
        lines.append("Enabled (not currently advertised):")
        for r in enabled_only:
            lines.append(f"  {r}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


def format_dns(dns: dict[str, Any]) -> str:
    """Format DNS configuration."""
    lines = []

    lines.append(f"MagicDNS: {'enabled' if dns.get('magic_dns') else 'disabled'}")

    nameservers = dns.get("nameservers", [])
    if nameservers:
        lines.append(f"Nameservers: {', '.join(nameservers)}")
    else:
        lines.append("Nameservers: (none)")

    search_paths = dns.get("search_paths", [])
    if search_paths:
        lines.append(f"Search paths: {', '.join(search_paths)}")

    split_dns = dns.get("split_dns", {})
    if split_dns:
        lines.append("Split DNS:")
        for domain, servers in split_dns.items():
            if isinstance(servers, list):
                lines.append(f"  {domain} → {', '.join(servers)}")
            else:
                lines.append(f"  {domain} → {servers}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# ACL / Policy
# ---------------------------------------------------------------------------


def format_acl(acl: dict[str, Any]) -> str:
    """Format ACL policy summary."""
    lines = []

    # Groups
    groups = acl.get("groups", {}) or acl.get("Groups", {})
    if groups:
        lines.append(f"Groups ({len(groups)}):")
        for name, members in list(groups.items())[:20]:
            member_count = len(members) if isinstance(members, list) else "?"
            lines.append(f"  {name} ({member_count} members)")

    # ACL rules
    acls = acl.get("acls", []) or acl.get("ACLs", [])
    if acls:
        lines.append(f"\nACL rules ({len(acls)}):")
        for i, rule in enumerate(acls[:30]):
            action = rule.get("action", "?")
            src = rule.get("src", [])
            dst = rule.get("dst", [])
            src_str = ", ".join(str(s) for s in src[:3])
            dst_str = ", ".join(str(d) for d in dst[:3])
            if len(src) > 3:
                src_str += f" +{len(src) - 3}"
            if len(dst) > 3:
                dst_str += f" +{len(dst) - 3}"
            lines.append(f"  [{action}] {src_str} → {dst_str}")

    # SSH rules
    ssh = acl.get("ssh", [])
    if ssh:
        lines.append(f"\nSSH rules ({len(ssh)}):")
        for rule in ssh[:10]:
            action = rule.get("action", "?")
            src = rule.get("src", [])
            dst = rule.get("dst", [])
            users = rule.get("users", [])
            lines.append(f"  [{action}] {', '.join(str(s) for s in src[:2])} → {', '.join(str(d) for d in dst[:2])}")
            if users:
                lines.append(f"    users: {', '.join(str(u) for u in users[:5])}")

    # Tag owners
    tag_owners = acl.get("tagOwners", {})
    if tag_owners:
        lines.append(f"\nTag owners ({len(tag_owners)}):")
        for tag, owners in list(tag_owners.items())[:15]:
            lines.append(f"  {tag}: {', '.join(str(o) for o in owners[:3])}")

    if not lines:
        return "(empty policy)"

    return "\n".join(lines)


def format_acl_validation(result: dict[str, Any]) -> str:
    """Format ACL validation result."""
    message = result.get("message", "")
    if message:
        return f"Validation: {message}"
    return "Validation: passed"


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------


def format_key_line(key: dict[str, Any]) -> str:
    """Format a single auth key as a compact line."""
    parts = []

    key_id = key.get("id", "?")
    parts.append(key_id)

    desc = key.get("description", "")
    if desc:
        parts.append(desc[:40])

    caps = key.get("capabilities", {})
    device_caps = caps.get("devices", {}).get("create", {})
    flags = []
    if device_caps.get("reusable"):
        flags.append("reusable")
    if device_caps.get("ephemeral"):
        flags.append("ephemeral")
    if device_caps.get("preauthorized"):
        flags.append("preauth")
    if flags:
        parts.append(",".join(flags))

    tags = device_caps.get("tags", [])
    if tags:
        tag_str = ",".join(t.replace("tag:", "") for t in tags[:3])
        parts.append(f"tags={tag_str}")

    if key.get("revoked"):
        parts.append("REVOKED")
    else:
        parts.append(f"expires={_short_date(key.get('expires'))}")

    return " | ".join(parts)


def format_key_list(keys: list[dict[str, Any]]) -> str:
    """Format a list of auth keys."""
    if not keys:
        return "(no auth keys)"
    return "\n".join(format_key_line(k) for k in keys)


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


def format_user_line(user: dict[str, Any]) -> str:
    """Format a single user as a compact line."""
    parts = []

    parts.append(user.get("displayName", "") or user.get("loginName", "?"))

    login = user.get("loginName", "")
    if login:
        parts.append(login)

    role = user.get("role", "")
    if role:
        parts.append(f"role={role}")

    status = user.get("status", "")
    if status:
        parts.append(status)

    device_count = user.get("deviceCount", 0)
    if device_count:
        parts.append(f"devices={device_count}")

    if user.get("currentlyConnected"):
        parts.append("online")
    else:
        parts.append(f"last={_time_ago(user.get('lastSeen'))}")

    return " | ".join(parts)


def format_user_list(users: list[dict[str, Any]]) -> str:
    """Format a list of users."""
    if not users:
        return "(no users)"
    return "\n".join(format_user_line(u) for u in users)


# ---------------------------------------------------------------------------
# Webhooks
# ---------------------------------------------------------------------------


def format_webhook_line(webhook: dict[str, Any]) -> str:
    """Format a single webhook as a compact line."""
    parts = []

    endpoint_id = webhook.get("endpointId", "?")
    parts.append(endpoint_id)

    url = webhook.get("endpointUrl", "")
    if url:
        # Truncate long URLs
        parts.append(url[:60] + ("…" if len(url) > 60 else ""))

    events = webhook.get("subscriptions", [])
    if events:
        parts.append(f"events={len(events)}")

    parts.append(f"created={_short_date(webhook.get('created'))}")

    return " | ".join(parts)


def format_webhook_list(webhooks: list[dict[str, Any]]) -> str:
    """Format a list of webhooks."""
    if not webhooks:
        return "(no webhooks)"
    return "\n".join(format_webhook_line(w) for w in webhooks)


# ---------------------------------------------------------------------------
# Audit Log
# ---------------------------------------------------------------------------


def format_audit_line(entry: dict[str, Any]) -> str:
    """Format a single audit log entry as a compact line."""
    parts = []

    parts.append(_short_date(entry.get("eventTime")) or "?")

    actor = entry.get("actor", {})
    actor_name = actor.get("displayName", "") or actor.get("loginName", "") or actor.get("id", "?")
    parts.append(actor_name)

    action = entry.get("type", "?")
    parts.append(action)

    target = entry.get("target", {})
    target_name = target.get("name", "") or target.get("id", "")
    if target_name:
        parts.append(target_name)

    return " | ".join(parts)


def format_audit_log(entries: list[dict[str, Any]]) -> str:
    """Format audit log entries."""
    if not entries:
        return "(no audit log entries)"
    return "\n".join(format_audit_line(e) for e in entries)
