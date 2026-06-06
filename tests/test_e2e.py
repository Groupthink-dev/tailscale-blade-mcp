"""Live end-to-end tier — DD-385 Phase 1 (blade live-hardening campaign).

These tests hit a REAL Tailscale tailnet and are skipped unless explicitly
opted in. They lock in the live-only defects the mocked suite passed straight
through (audit-log window shape, webhooks-null crash) plus the lowest-blast
mutation loop (auth-key create→delete) and the validate-only ACL path.

    TAILSCALE_E2E=1 TAILSCALE_API_KEY=tskey-… uv run pytest -m e2e

Safety contract (until DD-382 provides a disposable sandbox tailnet):
- **No ACL apply.** ``ts_acl_set`` is exercised validate-only here — lockout
  risk on a live tailnet makes apply a throwaway-tailnet-only operation (OQ-3).
- **Lowest-blast mutation only.** The sole write is an ephemeral, 300s-expiry,
  ``zz-``-described auth key that is deleted in the same test and confirmed gone.
- **Denylist hook.** Set ``TAILSCALE_E2E_DENY_TAILNETS`` (comma-separated) to
  abort if the resolved tailnet matches — the DD-382 production-host guard seam.
"""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.e2e

if not os.environ.get("TAILSCALE_E2E") or not os.environ.get("TAILSCALE_API_KEY"):
    pytest.skip("set TAILSCALE_E2E=1 + TAILSCALE_API_KEY to run live e2e", allow_module_level=True)

from tailscale_blade_mcp.client import TailscaleClient  # noqa: E402


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _deny_guard() -> None:
    deny = {t.strip() for t in os.environ.get("TAILSCALE_E2E_DENY_TAILNETS", "").split(",") if t.strip()}
    tailnet = os.environ.get("TAILSCALE_TAILNET", "-")
    if tailnet in deny:
        pytest.fail(f"refusing to run e2e against denylisted tailnet {tailnet!r}")


async def test_audit_log_live_window_no_400() -> None:
    """D1: the live logging endpoint demands start+end — the tool must not 400."""
    _deny_guard()
    client = TailscaleClient()
    try:
        entries = await client.get_audit_log(count=5, days=3)
        assert isinstance(entries, list)
    finally:
        await client.close()


async def test_webhooks_live_returns_list() -> None:
    """D2: empty tailnet emits {"webhooks": null} — must collapse to a list, not crash."""
    _deny_guard()
    client = TailscaleClient()
    try:
        result = await client.get_webhooks()
        assert isinstance(result, list)
    finally:
        await client.close()


async def test_acl_validate_live_roundtrip() -> None:
    """OQ-3: validate-only. Current policy passes; a bad group is rejected. No apply."""
    _deny_guard()
    client = TailscaleClient()
    try:
        current, etag = await client.get_acl_with_etag()
        assert etag is not None  # live GET surfaces the If-Match token
        passed = await client.validate_acl(current)
        assert not passed.get("message")  # empty/no message == passed
        bad = await client.validate_acl({"acls": [{"action": "accept", "src": ["group:nope"], "dst": ["*:*"]}]})
        assert "not found" in bad.get("message", "").lower()
    finally:
        await client.close()


async def test_key_create_delete_lowest_blast() -> None:
    """Lowest-blast reversible mutation: create→verify→delete→confirm-gone."""
    _deny_guard()
    client = TailscaleClient()
    try:
        created = await client.create_key(
            ephemeral=True, reusable=False, expiry_seconds=300, description="zz-dd385-e2e-probe"
        )
        kid = created["id"]
        assert created.get("key")  # secret present on create
        assert any(k.get("id") == kid for k in await client.get_keys())
        await client.delete_key(kid)
        assert not any(k.get("id") == kid for k in await client.get_keys())
    finally:
        await client.close()
