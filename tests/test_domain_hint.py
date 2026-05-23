"""Unit tests for DD-338 A.2.dom.c domain_hint pattern engine + YAML loader."""

from __future__ import annotations

from typing import Any

import pytest

from tailscale_blade_mcp.domain_hint import (
    Pattern,
    compute_domain_hint,
    load_patterns_from_yaml,
)


def _projector(record: dict[str, Any], field: str) -> Any:
    """Simple test projector — mirrors Tailscale device fields used in tests."""
    f = field.lower()
    if f == "hostname":
        return record.get("hostname")
    if f == "tags":
        v = record.get("tags")
        return v if isinstance(v, list) else None
    if f == "user":
        return record.get("user")
    return None


def test_empty_patterns_returns_none() -> None:
    """Empty pattern list ⇒ no hint."""
    record = {"hostname": "alpha", "tags": ["tag:server"]}
    assert compute_domain_hint(record, [], _projector) is None


def test_single_equals_match() -> None:
    """Equals op on a scalar field matches when value identical."""
    patterns = [Pattern(field="hostname", op="equals", value="alpha", domain="work")]
    record = {"hostname": "alpha"}
    assert compute_domain_hint(record, patterns, _projector) == "work"


def test_first_match_wins() -> None:
    """First pattern to match short-circuits — later patterns ignored."""
    patterns = [
        Pattern(field="tags", op="equals", value="tag:server", domain="work"),
        Pattern(field="hostname", op="contains", value="alpha", domain="home"),
    ]
    record = {"hostname": "alpha-host", "tags": ["tag:server"]}
    assert compute_domain_hint(record, patterns, _projector) == "work"


def test_contains_on_list_field() -> None:
    """``contains`` op on a list field matches when value substring of any element."""
    patterns = [Pattern(field="tags", op="contains", value=":prod", domain="work")]
    record = {"tags": ["tag:prod", "tag:server"]}
    assert compute_domain_hint(record, patterns, _projector) == "work"


def test_glob_wildcard_match() -> None:
    """``glob`` op uses ``fnmatch.fnmatchcase`` with wildcards."""
    patterns = [Pattern(field="hostname", op="glob", value="*.home", domain="home")]
    record = {"hostname": "router.home"}
    assert compute_domain_hint(record, patterns, _projector) == "home"


def test_projector_returns_none_skips_pattern() -> None:
    """Missing field ⇒ pattern silently skipped, fall through to next."""
    patterns = [
        Pattern(field="hostname", op="equals", value="alpha", domain="work"),
        Pattern(field="user", op="contains", value="@home", domain="home"),
    ]
    record = {"user": "alice@home.example.com"}  # no hostname
    assert compute_domain_hint(record, patterns, _projector) == "home"


def test_unknown_op_silently_skipped() -> None:
    """Defensive: unknown op string skipped, not raised — schema-drift safe."""
    patterns = [
        Pattern(field="hostname", op="bogus", value="alpha", domain="work"),
        Pattern(field="hostname", op="equals", value="alpha", domain="home"),
    ]
    record = {"hostname": "alpha"}
    assert compute_domain_hint(record, patterns, _projector) == "home"


def test_no_match_returns_none() -> None:
    """When no pattern matches and the record has the projected field, returns None."""
    patterns = [Pattern(field="hostname", op="equals", value="alpha", domain="work")]
    record = {"hostname": "beta"}
    assert compute_domain_hint(record, patterns, _projector) is None


# ---------------------------------------------------------------------------
# load_patterns_from_yaml
# ---------------------------------------------------------------------------


def test_yaml_loader_empty_string() -> None:
    """Empty input ⇒ empty list (Convention #22 graceful degradation)."""
    assert load_patterns_from_yaml("") == []
    assert load_patterns_from_yaml("   \n  ") == []


def test_yaml_loader_valid_patterns() -> None:
    """Well-formed YAML round-trips into Pattern dataclasses."""
    yaml_str = """
patterns:
  - field: tags
    op: equals
    value: tag:server
    domain: work
  - field: hostname
    op: glob
    value: "*.home"
    domain: home
"""
    patterns = load_patterns_from_yaml(yaml_str)
    assert len(patterns) == 2
    assert patterns[0] == Pattern(field="tags", op="equals", value="tag:server", domain="work")
    assert patterns[1] == Pattern(field="hostname", op="glob", value="*.home", domain="home")


def test_yaml_loader_malformed_yields_empty() -> None:
    """Parse error ⇒ empty list, no raise."""
    assert load_patterns_from_yaml("patterns: [unterminated") == []


def test_yaml_loader_missing_patterns_key() -> None:
    """``patterns`` key missing ⇒ empty list."""
    assert load_patterns_from_yaml("other_key: value") == []


def test_yaml_loader_partial_failures_skipped() -> None:
    """Per-pattern errors skip that entry; good entries still load."""
    yaml_str = """
patterns:
  - field: hostname
    op: equals
    value: alpha
    domain: work
  - missing_required_keys: true
  - field: tags
    op: contains
    value: ":prod"
    domain: home
"""
    patterns = load_patterns_from_yaml(yaml_str)
    assert len(patterns) == 2
    assert patterns[0].domain == "work"
    assert patterns[1].domain == "home"


def test_yaml_loader_non_mapping_root() -> None:
    """Top-level list (not mapping) ⇒ empty list."""
    assert load_patterns_from_yaml("- foo\n- bar") == []


# ---------------------------------------------------------------------------
# Tailscale-specific projector (smoke against server's projector)
# ---------------------------------------------------------------------------


def test_tailscale_projector_handles_user_record_loginname() -> None:
    """Server projector maps ``user`` field to either ``user`` or ``loginName``."""
    from tailscale_blade_mcp.server import _tailscale_field_projector

    # Device record uses ``user``
    device = {"user": "alice@example.com"}
    assert _tailscale_field_projector(device, "user") == "alice@example.com"

    # User-API record uses ``loginName``
    user = {"loginName": "bob@example.com"}
    assert _tailscale_field_projector(user, "user") == "bob@example.com"


def test_tailscale_projector_tags_list_passthrough() -> None:
    """Projector returns the list as-is for downstream candidate iteration."""
    from tailscale_blade_mcp.server import _tailscale_field_projector

    record = {"tags": ["tag:server", "tag:prod"]}
    assert _tailscale_field_projector(record, "tags") == ["tag:server", "tag:prod"]


def test_tailscale_projector_unknown_field() -> None:
    """Unknown field name ⇒ None (not raised)."""
    from tailscale_blade_mcp.server import _tailscale_field_projector

    assert _tailscale_field_projector({"hostname": "a"}, "totally-unknown") is None


def test_tailscale_record_id_prefers_nodeid() -> None:
    """``nodeId`` is preferred over legacy ``id``."""
    from tailscale_blade_mcp.server import _record_id

    assert _record_id({"nodeId": "n-abc", "id": "12345"}) == "n-abc"
    assert _record_id({"id": "12345"}) == "12345"
    assert _record_id({}) is None


@pytest.mark.parametrize(
    "rec,expected",
    [
        ({"nodeId": "n-1"}, "n-1"),
        ({"id": 42}, "42"),  # int coerced to str
        ({"nodeId": ""}, None),  # empty string falls through
        ({"nodeId": None, "id": "fallback"}, "fallback"),
    ],
)
def test_tailscale_record_id_edge_cases(rec: dict[str, Any], expected: str | None) -> None:
    from tailscale_blade_mcp.server import _record_id

    assert _record_id(rec) == expected
