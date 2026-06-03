"""DD-338 Phase A.1 — scope-tag filter + Track 3 _meta envelope tests.

Covers ts_devices, ts_device, ts_keys, ts_audit_log under client-side
scope filtering, with Track 3 _meta envelopes (canonical JSON-tail shape).
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest
import respx
from httpx import Response

from tailscale_blade_mcp.formatters import (
    append_meta,
    meta_envelope,
)
from tailscale_blade_mcp.models import (
    apply_scope_filter,
    parse_scope_tag_map,
    validate_scope,
)

# Assembler-side regex per spec (architect amendment 2026-05-21).
META_RE = re.compile(r"\n\n_meta: (\{.*\})$", re.DOTALL)


# ---------------------------------------------------------------------------
# parse_scope_tag_map + validate_scope unit tests
# ---------------------------------------------------------------------------


class TestScopeTagMap:
    def test_defaults_when_env_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TAILSCALE_SCOPE_INFRASTRUCTURE_TAGS", raising=False)
        monkeypatch.delenv("TAILSCALE_SCOPE_PERSONAL_TAGS", raising=False)
        monkeypatch.delenv("TAILSCALE_SCOPE_HOME_TAGS", raising=False)
        m = parse_scope_tag_map()
        assert "tag:groupthink-infra" in m["infrastructure"]
        assert "tag:stallari-host" in m["infrastructure"]
        assert m["personal"] == {"tag:personal"}
        assert m["home"] == {"tag:home", "tag:household"}

    def test_env_override_replaces_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TAILSCALE_SCOPE_INFRASTRUCTURE_TAGS", "tag:custom-infra,tag:other")
        m = parse_scope_tag_map()
        assert m["infrastructure"] == {"tag:custom-infra", "tag:other"}
        # Personal/home untouched, fall back to defaults.
        assert m["personal"] == {"tag:personal"}

    def test_env_whitespace_stripped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TAILSCALE_SCOPE_HOME_TAGS", " tag:home , tag:household ")
        m = parse_scope_tag_map()
        assert m["home"] == {"tag:home", "tag:household"}


class TestValidateScope:
    def test_none_returns_none(self) -> None:
        assert validate_scope(None) is None

    def test_known_scopes_canonicalise(self) -> None:
        assert validate_scope("infrastructure") == "infrastructure"
        assert validate_scope(" Personal ") == "personal"
        assert validate_scope("HOME") == "home"

    def test_public_unsupported(self) -> None:
        with pytest.raises(ValueError, match="public"):
            validate_scope("public")

    def test_unknown_scope_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown"):
            validate_scope("rocketship")


# ---------------------------------------------------------------------------
# apply_scope_filter unit tests
# ---------------------------------------------------------------------------


class TestApplyScopeFilter:
    def _items(self) -> list[dict[str, Any]]:
        return [
            {"name": "infra1", "tags": ["tag:groupthink-infra"]},
            {"name": "infra2", "tags": ["tag:stallari-host"]},
            {"name": "home1", "tags": ["tag:home"]},
            {"name": "personal-tagged", "tags": ["tag:personal"]},
            {"name": "untagged", "tags": []},
            {"name": "no-tag-field"},
            {"name": "experimental", "tags": ["tag:experimental"]},
        ]

    def test_scope_none_returns_all(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TAILSCALE_SCOPE_INFRASTRUCTURE_TAGS", raising=False)
        filtered, tags = apply_scope_filter(self._items(), None)
        assert len(filtered) == 7
        assert tags == []

    def test_infrastructure_strict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TAILSCALE_SCOPE_INFRASTRUCTURE_TAGS", raising=False)
        filtered, tags = apply_scope_filter(self._items(), "infrastructure")
        names = {x["name"] for x in filtered}
        assert names == {"infra1", "infra2"}
        # tags sorted ascending
        assert tags == sorted(tags)
        assert "tag:groupthink-infra" in tags

    def test_home_strict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TAILSCALE_SCOPE_HOME_TAGS", raising=False)
        filtered, _ = apply_scope_filter(self._items(), "home")
        assert {x["name"] for x in filtered} == {"home1"}

    def test_personal_includes_untagged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TAILSCALE_SCOPE_PERSONAL_TAGS", raising=False)
        filtered, _ = apply_scope_filter(self._items(), "personal")
        names = {x["name"] for x in filtered}
        # untagged + no-tag-field + tag:personal pass; tag:experimental does not.
        assert names == {"personal-tagged", "untagged", "no-tag-field"}

    def test_experimental_excluded_from_infrastructure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TAILSCALE_SCOPE_INFRASTRUCTURE_TAGS", raising=False)
        filtered, _ = apply_scope_filter(self._items(), "infrastructure")
        assert all(x["name"] != "experimental" for x in filtered)

    def test_env_override_displaces_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TAILSCALE_SCOPE_INFRASTRUCTURE_TAGS", "tag:experimental")
        filtered, tags = apply_scope_filter(self._items(), "infrastructure")
        assert {x["name"] for x in filtered} == {"experimental"}
        assert tags == ["tag:experimental"]

    def test_custom_tag_key(self) -> None:
        items = [{"id": "a", "labels": ["x"]}, {"id": "b", "labels": ["y"]}]
        filtered, _ = apply_scope_filter(
            items,
            "infrastructure",
            scope_tag_map={"infrastructure": {"x"}, "personal": set(), "home": set()},
            tag_key="labels",
        )
        assert [i["id"] for i in filtered] == ["a"]


# ---------------------------------------------------------------------------
# _meta envelope formatter tests
# ---------------------------------------------------------------------------


class TestMetaEnvelope:
    def test_meta_envelope_shape(self) -> None:
        rendered = meta_envelope(
            matched_total=14,
            returned=4,
            latency_ms=234,
            filtered_by=["scope=infrastructure", "tags=tag:groupthink-infra"],
        )
        assert rendered.startswith("_meta: ")
        # Body must parse as JSON.
        parsed = json.loads(rendered[len("_meta: ") :])
        assert parsed["matched_total"] == 14
        # Canonical builder alphabetically sorts filtered_by.
        assert parsed["filtered_by"] == sorted(["scope=infrastructure", "tags=tag:groupthink-infra"])

    def test_append_envelope_uses_double_newline(self) -> None:
        envelope = meta_envelope(matched_total=1, returned=1, latency_ms=5, filtered_by=[])
        out = append_meta("payload-line-1\npayload-line-2", envelope)
        match = META_RE.search(out)
        assert match is not None
        body = json.loads(match.group(1))
        assert body["matched_total"] == 1

    def test_append_envelope_empty_payload(self) -> None:
        # DD-338 Phase E.python: canonical append_meta always joins body+\n\n+envelope.
        # The original local helper short-circuited on empty body; the canonical lib
        # emits the leading \n\n unconditionally. The assembler-side regex
        # r"\n\n_meta: (\{.*\})$" still matches at end-of-string in either case.
        envelope = meta_envelope(matched_total=0, returned=0, latency_ms=1, filtered_by=[])
        out = append_meta("", envelope)
        match = META_RE.search(out)
        assert match is not None
        body = json.loads(match.group(1))
        assert body["matched_total"] == 0


# ---------------------------------------------------------------------------
# End-to-end tool tests with respx-mocked HTTP
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_env_with_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """API key + reset scope env vars so defaults apply."""
    monkeypatch.setenv("TAILSCALE_API_KEY", "tskey-api-test123")
    monkeypatch.delenv("TAILSCALE_TAILNET", raising=False)
    monkeypatch.delenv("TAILSCALE_WRITE_ENABLED", raising=False)
    monkeypatch.delenv("TAILSCALE_SCOPE_INFRASTRUCTURE_TAGS", raising=False)
    monkeypatch.delenv("TAILSCALE_SCOPE_PERSONAL_TAGS", raising=False)
    monkeypatch.delenv("TAILSCALE_SCOPE_HOME_TAGS", raising=False)


@pytest.fixture()
def reset_client() -> Any:
    """Drop the singleton client before/after each test (per-test env)."""
    import tailscale_blade_mcp.server as srv

    srv._client = None
    yield
    srv._client = None


def _devices_payload() -> dict[str, Any]:
    return {
        "devices": [
            {
                "nodeId": "n1",
                "id": "1",
                "name": "infra-a.tail.ts.net",
                "hostname": "infra-a",
                "os": "Linux",
                "addresses": ["100.0.0.1"],
                "clientVersion": "1.76.0",
                "connectedToControl": True,
                "authorized": True,
                "keyExpiryDisabled": False,
                "expires": "2026-12-01T00:00:00Z",
                "tags": ["tag:groupthink-infra"],
                "user": "ops@example.com",
            },
            {
                "nodeId": "n2",
                "id": "2",
                "name": "infra-b.tail.ts.net",
                "hostname": "infra-b",
                "os": "Linux",
                "addresses": ["100.0.0.2"],
                "clientVersion": "1.76.0",
                "connectedToControl": True,
                "authorized": True,
                "keyExpiryDisabled": False,
                "expires": "2026-12-01T00:00:00Z",
                "tags": ["tag:stallari-host"],
                "user": "ops@example.com",
            },
            {
                "nodeId": "n3",
                "id": "3",
                "name": "laptop.tail.ts.net",
                "hostname": "laptop",
                "os": "macOS",
                "addresses": ["100.0.0.3"],
                "clientVersion": "1.76.0",
                "connectedToControl": True,
                "authorized": True,
                "keyExpiryDisabled": False,
                "expires": "2026-12-01T00:00:00Z",
                "tags": [],
                "user": "alice@example.com",
            },
            {
                "nodeId": "n4",
                "id": "4",
                "name": "homehub.tail.ts.net",
                "hostname": "homehub",
                "os": "Linux",
                "addresses": ["100.0.0.4"],
                "clientVersion": "1.76.0",
                "connectedToControl": True,
                "authorized": True,
                "keyExpiryDisabled": False,
                "expires": "2026-12-01T00:00:00Z",
                "tags": ["tag:home"],
                "user": "alice@example.com",
            },
            {
                "nodeId": "n5",
                "id": "5",
                "name": "lab.tail.ts.net",
                "hostname": "lab",
                "os": "Linux",
                "addresses": ["100.0.0.5"],
                "clientVersion": "1.76.0",
                "connectedToControl": True,
                "authorized": True,
                "keyExpiryDisabled": False,
                "expires": "2026-12-01T00:00:00Z",
                "tags": ["tag:experimental"],
                "user": "alice@example.com",
            },
        ]
    }


def _parse_meta(text: str) -> dict[str, Any]:
    match = META_RE.search(text)
    assert match is not None, f"no _meta envelope found in:\n{text!r}"
    return json.loads(match.group(1))


@pytest.mark.anyio
class TestTsDevicesScope:
    """End-to-end ts_devices tool with respx-mocked Tailscale API."""

    @pytest.fixture
    def anyio_backend(self) -> str:
        return "asyncio"

    @respx.mock
    async def test_no_scope_returns_all_with_envelope(
        self,
        mock_env_with_defaults: None,
        reset_client: None,
    ) -> None:
        from tailscale_blade_mcp.server import ts_devices

        respx.get("https://api.tailscale.com/api/v2/tailnet/-/devices?fields=all").mock(
            return_value=Response(200, json=_devices_payload())
        )

        text = await ts_devices()
        meta = _parse_meta(text)
        assert meta["matched_total"] == 5
        assert meta["returned"] == 5
        # DD-338 Phase E.python: canonical lib treats redactions as list[str] of
        # reason codes; the prior integer count is recoverable from
        # matched_total - returned. Tailscale call-sites pass redactions=[].
        assert meta["redactions"] == []
        assert meta["matched_total"] - meta["returned"] == 0
        assert meta["filtered_by"] == []
        assert "latency_ms" in meta

    @respx.mock
    async def test_scope_infrastructure_filters_to_matching_tags(
        self,
        mock_env_with_defaults: None,
        reset_client: None,
    ) -> None:
        from tailscale_blade_mcp.server import ts_devices

        respx.get("https://api.tailscale.com/api/v2/tailnet/-/devices?fields=all").mock(
            return_value=Response(200, json=_devices_payload())
        )

        text = await ts_devices(scope="infrastructure")
        meta = _parse_meta(text)
        assert meta["matched_total"] == 5
        assert meta["returned"] == 2
        assert meta["redactions"] == []
        assert meta["matched_total"] - meta["returned"] == 3
        assert "scope=infrastructure" in meta["filtered_by"]
        # tags facet present with sorted tag list joined by ","
        tags_facet = [f for f in meta["filtered_by"] if f.startswith("tags=")]
        assert tags_facet
        # Payload contains the 2 infra device hostnames
        assert "infra-a" in text
        assert "infra-b" in text
        assert "laptop" not in text
        assert "lab" not in text

    @respx.mock
    async def test_scope_personal_includes_untagged(
        self,
        mock_env_with_defaults: None,
        reset_client: None,
    ) -> None:
        from tailscale_blade_mcp.server import ts_devices

        respx.get("https://api.tailscale.com/api/v2/tailnet/-/devices?fields=all").mock(
            return_value=Response(200, json=_devices_payload())
        )

        text = await ts_devices(scope="personal")
        meta = _parse_meta(text)
        # laptop (untagged) passes via untagged-pass-through; no tag:personal in fixture
        assert meta["returned"] == 1
        assert "laptop" in text

    @respx.mock
    async def test_scope_public_rejected(
        self,
        mock_env_with_defaults: None,
        reset_client: None,
    ) -> None:
        from tailscale_blade_mcp.server import ts_devices

        # No HTTP mock — call should fail before reaching the API.
        text = await ts_devices(scope="public")
        assert text.startswith("Error:")
        assert "public" in text

    @respx.mock
    async def test_env_override_displaces_defaults(
        self,
        mock_env_with_defaults: None,
        reset_client: None,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from tailscale_blade_mcp.server import ts_devices

        monkeypatch.setenv("TAILSCALE_SCOPE_INFRASTRUCTURE_TAGS", "tag:experimental")
        respx.get("https://api.tailscale.com/api/v2/tailnet/-/devices?fields=all").mock(
            return_value=Response(200, json=_devices_payload())
        )

        text = await ts_devices(scope="infrastructure")
        meta = _parse_meta(text)
        # Only the experimental-tagged device matches now.
        assert meta["returned"] == 1
        assert "lab" in text
        # filtered_by carries the override tag
        tags_facet = next(f for f in meta["filtered_by"] if f.startswith("tags="))
        assert "tag:experimental" in tags_facet


@pytest.mark.anyio
class TestTsDeviceSingle:
    @pytest.fixture
    def anyio_backend(self) -> str:
        return "asyncio"

    @respx.mock
    async def test_single_device_envelope(
        self,
        mock_env_with_defaults: None,
        reset_client: None,
    ) -> None:
        from tailscale_blade_mcp.server import ts_device

        respx.get("https://api.tailscale.com/api/v2/device/n1?fields=all").mock(
            return_value=Response(200, json=_devices_payload()["devices"][0])
        )

        text = await ts_device(device_id="n1")
        meta = _parse_meta(text)
        assert meta["matched_total"] == 1
        assert meta["returned"] == 1
        # DD-338 Phase E.python: canonical lib treats redactions as list[str] of
        # reason codes; the prior integer count is recoverable from
        # matched_total - returned. Tailscale call-sites pass redactions=[].
        assert meta["redactions"] == []
        assert meta["matched_total"] - meta["returned"] == 0
        assert "device_id=n1" in meta["filtered_by"]


@pytest.mark.anyio
class TestTsKeysScope:
    @pytest.fixture
    def anyio_backend(self) -> str:
        return "asyncio"

    @respx.mock
    async def test_keys_scope_infrastructure(
        self,
        mock_env_with_defaults: None,
        reset_client: None,
    ) -> None:
        from tailscale_blade_mcp.server import ts_keys

        keys_payload = {
            "keys": [
                {
                    "id": "k-infra",
                    "description": "infra runner",
                    "capabilities": {
                        "devices": {
                            "create": {
                                "reusable": True,
                                "tags": ["tag:groupthink-infra"],
                            }
                        }
                    },
                    "revoked": False,
                    "expires": "2026-12-01T00:00:00Z",
                },
                {
                    "id": "k-home",
                    "description": "home key",
                    "capabilities": {
                        "devices": {
                            "create": {
                                "reusable": False,
                                "tags": ["tag:home"],
                            }
                        }
                    },
                    "revoked": False,
                    "expires": "2026-12-01T00:00:00Z",
                },
                {
                    "id": "k-untagged",
                    "description": "no tags",
                    "capabilities": {"devices": {"create": {"reusable": False}}},
                    "revoked": False,
                    "expires": "2026-12-01T00:00:00Z",
                },
            ]
        }
        respx.get("https://api.tailscale.com/api/v2/tailnet/-/keys").mock(return_value=Response(200, json=keys_payload))

        text = await ts_keys(scope="infrastructure")
        meta = _parse_meta(text)
        assert meta["matched_total"] == 3
        assert meta["returned"] == 1
        assert meta["redactions"] == []
        assert meta["matched_total"] - meta["returned"] == 2
        assert "k-infra" in text
        assert "k-home" not in text


@pytest.mark.anyio
class TestTsAuditLogScope:
    @pytest.fixture
    def anyio_backend(self) -> str:
        return "asyncio"

    @respx.mock
    async def test_audit_log_no_scope_skips_secondary_fetch(
        self,
        mock_env_with_defaults: None,
        reset_client: None,
    ) -> None:
        from tailscale_blade_mcp.server import ts_audit_log

        # NB: matches the actual URL with ?count=50 query string.
        respx.get("https://api.tailscale.com/api/v2/tailnet/-/logging/configuration?count=50").mock(
            return_value=Response(
                200,
                json={
                    "logs": [
                        {
                            "eventTime": "2026-04-11T10:00:00Z",
                            "type": "DeviceAuthorized",
                            "actor": {"loginName": "alice@example.com"},
                            "target": {"id": "n1", "type": "node", "name": "infra-a"},
                        }
                    ]
                },
            )
        )

        text = await ts_audit_log()
        meta = _parse_meta(text)
        assert meta["matched_total"] == 1
        assert meta["returned"] == 1
        assert "count=50" in meta["filtered_by"]
        assert "scope=" not in str(meta["filtered_by"])

    @respx.mock
    async def test_audit_log_scope_filters_via_device_tag_map(
        self,
        mock_env_with_defaults: None,
        reset_client: None,
    ) -> None:
        from tailscale_blade_mcp.server import ts_audit_log

        respx.get("https://api.tailscale.com/api/v2/tailnet/-/logging/configuration?count=50").mock(
            return_value=Response(
                200,
                json={
                    "logs": [
                        {
                            "eventTime": "2026-04-11T10:00:00Z",
                            "type": "DeviceAuthorized",
                            "actor": {"loginName": "alice@example.com"},
                            "target": {
                                "id": "n1",
                                "type": "node",
                                "name": "infra-a",
                            },
                        },
                        {
                            "eventTime": "2026-04-11T10:01:00Z",
                            "type": "DeviceAuthorized",
                            "actor": {"loginName": "alice@example.com"},
                            "target": {
                                "id": "n4",
                                "type": "node",
                                "name": "homehub",
                            },
                        },
                        {
                            "eventTime": "2026-04-11T10:02:00Z",
                            "type": "DeviceAuthorized",
                            "actor": {"loginName": "alice@example.com"},
                            "target": {
                                "id": "n5",
                                "type": "node",
                                "name": "lab",
                            },
                        },
                    ]
                },
            )
        )
        respx.get("https://api.tailscale.com/api/v2/tailnet/-/devices?fields=all").mock(
            return_value=Response(200, json=_devices_payload())
        )

        text = await ts_audit_log(scope="infrastructure")
        meta = _parse_meta(text)
        assert meta["matched_total"] == 3
        assert meta["returned"] == 1  # only n1 has tag:groupthink-infra
        assert meta["redactions"] == []
        assert meta["matched_total"] - meta["returned"] == 2
        assert "infra-a" in text
        assert "homehub" not in text
        assert "lab" not in text
