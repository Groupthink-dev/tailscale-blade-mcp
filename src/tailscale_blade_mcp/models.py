"""Shared constants, types, and gates for Tailscale Blade MCP server."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

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
