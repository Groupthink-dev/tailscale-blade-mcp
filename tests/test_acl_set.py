"""Tests for ts_acl_set — ACL apply path (P7 7a).

Covers the write gate, mandatory pre-apply validation, optimistic-concurrency
If-Match behaviour, the 412 re-fetch surface, and the overwrite escape hatch.
End-to-end via respx-mocked HTTP so header assertions (If-Match, Content-Type)
and "did we POST?" assertions are real.
"""

from __future__ import annotations

import json
import re
from typing import Any

import pytest
import respx
from httpx import Response

ACL_URL = "https://api.tailscale.com/api/v2/tailnet/-/acl"
VALIDATE_URL = "https://api.tailscale.com/api/v2/tailnet/-/acl/validate"

META_RE = re.compile(r"\n\n_meta: (\{.*\})$", re.DOTALL)

SAMPLE_POLICY: dict[str, Any] = {
    "acls": [
        {"action": "accept", "src": ["group:admin"], "dst": ["*:*"]},
        {"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]},
    ],
    "tagOwners": {"tag:server": ["group:admin"]},
    "tests": [{"src": "alice@example.com", "accept": ["tag:server:22"]}],
}
POLICY_JSON = json.dumps(SAMPLE_POLICY)


@pytest.fixture()
def mock_env_write(monkeypatch: pytest.MonkeyPatch) -> None:
    """API key + write enabled + default tailnet."""
    monkeypatch.setenv("TAILSCALE_API_KEY", "tskey-api-test123")
    monkeypatch.setenv("TAILSCALE_WRITE_ENABLED", "true")
    monkeypatch.delenv("TAILSCALE_TAILNET", raising=False)


@pytest.fixture()
def mock_env_nowrite(monkeypatch: pytest.MonkeyPatch) -> None:
    """API key set, writes disabled."""
    monkeypatch.setenv("TAILSCALE_API_KEY", "tskey-api-test123")
    monkeypatch.delenv("TAILSCALE_WRITE_ENABLED", raising=False)
    monkeypatch.delenv("TAILSCALE_TAILNET", raising=False)


@pytest.fixture()
def reset_client() -> Any:
    """Drop the singleton client before/after each test (per-test env)."""
    import tailscale_blade_mcp.server as srv

    srv._client = None
    yield
    srv._client = None


def _parse_meta(text: str) -> dict[str, Any]:
    match = META_RE.search(text)
    assert match is not None, f"no _meta envelope found in:\n{text!r}"
    return json.loads(match.group(1))


@pytest.mark.anyio
class TestTsAclSet:
    @pytest.fixture
    def anyio_backend(self) -> str:
        return "asyncio"

    @respx.mock
    async def test_write_disabled_returns_guard(self, mock_env_nowrite: None, reset_client: None) -> None:
        from tailscale_blade_mcp.server import ts_acl_set

        validate = respx.post(VALIDATE_URL)
        apply = respx.post(ACL_URL)

        result = await ts_acl_set(POLICY_JSON)

        assert "disabled" in result.lower()
        assert "TAILSCALE_WRITE_ENABLED" in result
        # Gate is checked first — no API traffic at all.
        assert not validate.called
        assert not apply.called

    @respx.mock
    async def test_invalid_json_refuses(self, mock_env_write: None, reset_client: None) -> None:
        from tailscale_blade_mcp.server import ts_acl_set

        validate = respx.post(VALIDATE_URL)
        apply = respx.post(ACL_URL)

        result = await ts_acl_set("{not valid json")

        assert "Invalid JSON" in result
        assert not validate.called
        assert not apply.called

    @respx.mock
    async def test_happy_path_sends_if_match_and_content_type(self, mock_env_write: None, reset_client: None) -> None:
        from tailscale_blade_mcp.server import ts_acl_set

        respx.post(VALIDATE_URL).mock(return_value=Response(200, json={}))
        respx.get(ACL_URL).mock(return_value=Response(200, json=SAMPLE_POLICY, headers={"ETag": "etag-v1"}))
        apply = respx.post(ACL_URL).mock(return_value=Response(200, json=SAMPLE_POLICY, headers={"ETag": "etag-v2"}))

        result = await ts_acl_set(POLICY_JSON)

        assert "Applied ACL policy." in result
        assert "etag-v2" in result
        assert "Rules: 2" in result
        assert "tagOwners: 1" in result
        assert "tests: 1" in result

        # The POST carried the fetched ETag as If-Match + a JSON content type.
        assert apply.called
        req = apply.calls.last.request
        assert req.headers.get("if-match") == "etag-v1"
        assert "application/json" in req.headers.get("content-type", "")

        meta = _parse_meta(result)
        assert meta["matched_total"] == 1
        assert meta["returned"] == 1
        assert "concurrency_guard=if-match" in meta["filtered_by"]

    @respx.mock
    async def test_explicit_if_match_is_used(self, mock_env_write: None, reset_client: None) -> None:
        from tailscale_blade_mcp.server import ts_acl_set

        respx.post(VALIDATE_URL).mock(return_value=Response(200, json={}))
        get_acl = respx.get(ACL_URL)
        apply = respx.post(ACL_URL).mock(return_value=Response(200, json=SAMPLE_POLICY, headers={"ETag": "etag-new"}))

        result = await ts_acl_set(POLICY_JSON, if_match="caller-etag")

        assert "Applied ACL policy." in result
        # Caller supplied an ETag — no auto-fetch needed.
        assert not get_acl.called
        assert apply.calls.last.request.headers.get("if-match") == "caller-etag"

    @respx.mock
    async def test_validation_failure_refuses_without_posting(self, mock_env_write: None, reset_client: None) -> None:
        from tailscale_blade_mcp.server import ts_acl_set

        respx.post(VALIDATE_URL).mock(return_value=Response(200, json={"message": 'syntax error: unexpected "}"'}))
        get_acl = respx.get(ACL_URL)
        apply = respx.post(ACL_URL)

        result = await ts_acl_set(POLICY_JSON)

        assert "Refused" in result
        assert "validation failed" in result
        assert "NOT applied" in result
        assert 'unexpected "}"' in result
        # Refused before any ETag fetch or apply POST.
        assert not get_acl.called
        assert not apply.called

    @respx.mock
    async def test_412_surfaces_refetch_message(self, mock_env_write: None, reset_client: None) -> None:
        from tailscale_blade_mcp.server import ts_acl_set

        respx.post(VALIDATE_URL).mock(return_value=Response(200, json={}))
        respx.get(ACL_URL).mock(return_value=Response(200, json=SAMPLE_POLICY, headers={"ETag": "etag-stale"}))
        respx.post(ACL_URL).mock(return_value=Response(412, text="precondition failed"))

        result = await ts_acl_set(POLICY_JSON)

        assert "412" in result
        assert "changed since you read it" in result.lower()
        assert "re-fetch" in result.lower()

    @respx.mock
    async def test_allow_overwrite_concurrent_omits_if_match(self, mock_env_write: None, reset_client: None) -> None:
        from tailscale_blade_mcp.server import ts_acl_set

        respx.post(VALIDATE_URL).mock(return_value=Response(200, json={}))
        get_acl = respx.get(ACL_URL)
        apply = respx.post(ACL_URL).mock(
            return_value=Response(200, json=SAMPLE_POLICY, headers={"ETag": "etag-forced"})
        )

        result = await ts_acl_set(POLICY_JSON, allow_overwrite_concurrent=True)

        assert "Applied ACL policy." in result
        assert "WITHOUT If-Match" in result
        # No ETag fetch, and the POST carried no If-Match header.
        assert not get_acl.called
        assert apply.called
        assert "if-match" not in {k.lower() for k in apply.calls.last.request.headers.keys()}

        meta = _parse_meta(result)
        assert "concurrency_guard=off" in meta["filtered_by"]

    @respx.mock
    async def test_403_notes_write_scope(self, mock_env_write: None, reset_client: None) -> None:
        from tailscale_blade_mcp.server import ts_acl_set

        respx.post(VALIDATE_URL).mock(return_value=Response(200, json={}))
        respx.get(ACL_URL).mock(return_value=Response(200, json=SAMPLE_POLICY, headers={"ETag": "etag-v1"}))
        respx.post(ACL_URL).mock(return_value=Response(403, text="forbidden"))

        result = await ts_acl_set(POLICY_JSON)

        assert "Error" in result
        assert "scope" in result.lower()
        assert "write" in result.lower()
