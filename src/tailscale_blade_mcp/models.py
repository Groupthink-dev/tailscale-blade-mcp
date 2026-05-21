"""Shared constants, types, and gates for Tailscale Blade MCP server."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_API_BASE = "https://api.tailscale.com/api/v2"


@dataclass
class TailscaleConfig:
    """Configuration for a Tailscale API connection."""

    api_key: str
    tailnet: str = "-"
    api_base: str = DEFAULT_API_BASE


def parse_config() -> TailscaleConfig:
    """Parse Tailscale configuration from environment variables.

    Required:
        TAILSCALE_API_KEY — API access token (tskey-api-*) or OAuth bearer token

    Optional:
        TAILSCALE_TAILNET — tailnet name or "-" for auto-detect (default: "-")
        TAILSCALE_API_BASE — API base URL (default: https://api.tailscale.com/api/v2)
    """
    api_key = os.environ.get("TAILSCALE_API_KEY", "").strip()
    if not api_key:
        raise ValueError(
            "Tailscale API key not configured. Set TAILSCALE_API_KEY to your API access token (tskey-api-*)."
        )

    tailnet = os.environ.get("TAILSCALE_TAILNET", "-").strip() or "-"
    api_base = os.environ.get("TAILSCALE_API_BASE", DEFAULT_API_BASE).strip()

    return TailscaleConfig(api_key=api_key, tailnet=tailnet, api_base=api_base)


# ---------------------------------------------------------------------------
# Write gate
# ---------------------------------------------------------------------------


def is_write_enabled() -> bool:
    """Check whether write operations are enabled."""
    return os.environ.get("TAILSCALE_WRITE_ENABLED", "").strip().lower() == "true"


def require_write() -> str | None:
    """Return an error message if writes are disabled, else None."""
    if is_write_enabled():
        return None
    return "Write operations disabled. Set TAILSCALE_WRITE_ENABLED=true to enable."


# ---------------------------------------------------------------------------
# DD-278 scope-tag mapping (DD-338 Phase A.1)
# ---------------------------------------------------------------------------

# Per-scope default Tailscale tag sets. Override via comma-separated env vars:
#   TAILSCALE_SCOPE_INFRASTRUCTURE_TAGS=tag:foo,tag:bar
#   TAILSCALE_SCOPE_PERSONAL_TAGS=tag:personal
#   TAILSCALE_SCOPE_HOME_TAGS=tag:home
# Empty / unset env var → falls back to the per-scope default below.
_DEFAULT_SCOPE_TAGS: dict[str, set[str]] = {
    "infrastructure": {
        "tag:groupthink-infra",
        "tag:groupthink-runner",
        "tag:groupthink-build",
        "tag:infra-server",
        "tag:stallari-host",
    },
    "personal": {"tag:personal"},
    "home": {"tag:home", "tag:household"},
}

# Scopes recognised by the filter but explicitly unsupported on Tailscale devices.
_UNSUPPORTED_SCOPES: frozenset[str] = frozenset({"public"})


def parse_scope_tag_map() -> dict[str, set[str]]:
    """Return the scope→tag-set mapping, honouring env-var overrides.

    Comma-separated tag list per scope. Whitespace around individual tags is
    stripped. Empty / unset env var falls back to the per-scope default.
    Personal scope's "untagged passes through" behaviour is a hardcoded
    special case in apply_scope_filter, not driven by env config.
    """
    mapping: dict[str, set[str]] = {}
    env_map = {
        "infrastructure": "TAILSCALE_SCOPE_INFRASTRUCTURE_TAGS",
        "personal": "TAILSCALE_SCOPE_PERSONAL_TAGS",
        "home": "TAILSCALE_SCOPE_HOME_TAGS",
    }
    for scope, env_var in env_map.items():
        raw = os.environ.get(env_var, "").strip()
        if raw:
            tags = {part.strip() for part in raw.split(",") if part.strip()}
            mapping[scope] = tags if tags else set(_DEFAULT_SCOPE_TAGS[scope])
        else:
            mapping[scope] = set(_DEFAULT_SCOPE_TAGS[scope])
    return mapping


def validate_scope(scope: str | None) -> str | None:
    """Validate a scope value. Returns canonical scope name or raises ValueError.

    None → None (no-op, returns None).
    Unsupported scope (e.g. "public") → ValueError.
    Unknown scope → ValueError.
    """
    if scope is None:
        return None
    s = scope.strip().lower()
    if s in _UNSUPPORTED_SCOPES:
        raise ValueError(f"scope={s} is not applicable to Tailscale devices")
    if s not in _DEFAULT_SCOPE_TAGS:
        valid = sorted(_DEFAULT_SCOPE_TAGS.keys())
        raise ValueError(f"scope={s} is unknown. Valid scopes: {', '.join(valid)}")
    return s


def apply_scope_filter(
    items: list[dict[str, Any]],
    scope: str | None,
    scope_tag_map: dict[str, set[str]] | None = None,
    tag_key: str = "tags",
) -> tuple[list[dict[str, Any]], list[str]]:
    """Apply DD-278 scope filter client-side after fetch.

    Returns (filtered_items, scope_tag_list) where scope_tag_list is the
    sorted list of tags the filter matched against (for _meta envelope
    filtered_by population). When scope is None, returns (items, []).

    Personal scope special-case: a device/key with empty/missing tags
    passes through (most user laptops/phones are untagged in typical
    tailnets; tagged devices are usually infrastructure).
    """
    if scope is None:
        return items, []

    scope_canonical = validate_scope(scope)
    if scope_canonical is None:
        return items, []

    if scope_tag_map is None:
        scope_tag_map = parse_scope_tag_map()

    tag_set = scope_tag_map.get(scope_canonical, set())
    tag_list_sorted = sorted(tag_set)

    filtered: list[dict[str, Any]] = []
    for item in items:
        raw_tags = item.get(tag_key) or []
        item_tags = set(raw_tags) if isinstance(raw_tags, list) else set()

        if scope_canonical == "personal":
            # Personal scope: matches the tag set OR passes-through untagged
            if not item_tags or item_tags & tag_set:
                filtered.append(item)
        else:
            # Infrastructure / home: strict intersection with the tag set
            if item_tags & tag_set:
                filtered.append(item)

    return filtered, tag_list_sorted
