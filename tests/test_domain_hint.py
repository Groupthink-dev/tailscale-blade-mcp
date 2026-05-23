"""Unit tests for DD-338 A.2.dom.c domain_hint pattern engine + YAML loader.

DD-338 Phase E.python correction: blade-level integration tests against the
local ``compute_domain_hint`` wrapper in :mod:`tailscale_blade_mcp.server`,
which pre-projects Tailscale's record shapes via ``_tailscale_field_projector``
before delegating to the canonical 2-arg helper. The projector handles
(a) case-insensitive lookups, (b) ``loginName`` → ``user`` aliasing across
device vs user records, and (c) ``nodeId`` / ``id`` fallback. The canonical
lib's dot-path navigation alone cannot do case-insensitive lookup or logical
field aliasing.
"""

from __future__ import annotations

from typing import Any

import pytest
from stallari_mcp_helpers import Pattern, load_patterns_from_yaml

from tailscale_blade_mcp.server import (
    _record_id,
    _tailscale_field_projector,
    compute_domain_hint,
)


def _projector(record: dict[str, Any], field: str) -> Any:
    """Test-side projector wrapping server._tailscale_field_projector — keeps
    tests explicit about the closure binding for the 3-arg wrapper."""
    return _tailscale_field_projector(record, field)


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
        Pattern(field="hostname", op="bogus", value="alpha", domain="work"),  # type: ignore[arg-type]
        Pattern(field="hostname", op="equals", value="alpha", domain="home"),
    ]
    record = {"hostname": "alpha"}
    assert compute_domain_hint(record, patterns, _projector) == "home"


def test_no_match_returns_none() -> None:
    """When no pattern matches and the record has the projected field, returns None."""
    patterns = [Pattern(field="hostname", op="equals", value="alpha", domain="work")]
    record = {"hostname": "beta"}
    assert compute_domain_hint(record, patterns, _projector) is None


def test_compute_domain_hint_default_projector_arg() -> None:
    """Wrapper's default projector arg uses server._tailscale_field_projector
    — covers in-tool call-sites that omit the explicit projector."""
    patterns = [Pattern(field="hostname", op="equals", value="alpha", domain="work")]
    record = {"hostname": "alpha"}
    assert compute_domain_hint(record, patterns) == "work"


def test_compute_domain_hint_case_insensitive_field() -> None:
    """Projector lowercases the field name; ``Hostname`` resolves the same as ``hostname``.

    This is one of the load-bearing reasons the wrapper exists — the
    canonical lib's dot-path navigation is case-sensitive and would
    miss ``Hostname``-cased patterns silently.
    """
    patterns = [Pattern(field="Hostname", op="equals", value="alpha", domain="work")]
    record = {"hostname": "alpha"}
    assert compute_domain_hint(record, patterns, _projector) == "work"


def test_compute_domain_hint_user_alias_on_user_record() -> None:
    """``user`` field on a User-API record reads from ``loginName`` (alias).

    Another load-bearing reason for the wrapper — without aliasing, patterns
    against ``user`` would silently fail on user records since they expose
    ``loginName`` not ``user``.
    """
    patterns = [Pattern(field="user", op="contains", value="@example.com", domain="work")]
    record = {"loginName": "bob@example.com"}
    assert compute_domain_hint(record, patterns, _projector) == "work"


# ---------------------------------------------------------------------------
# load_patterns_from_yaml (canonical lib — smoke for blade-relevant shapes)
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
# Tailscale-specific projector (direct smoke against server's projector)
# ---------------------------------------------------------------------------


def test_tailscale_projector_handles_user_record_loginname() -> None:
    """Server projector maps ``user`` field to either ``user`` or ``loginName``."""
    # Device record uses ``user``
    device = {"user": "alice@example.com"}
    assert _tailscale_field_projector(device, "user") == "alice@example.com"

    # User-API record uses ``loginName``
    user = {"loginName": "bob@example.com"}
    assert _tailscale_field_projector(user, "user") == "bob@example.com"


def test_tailscale_projector_tags_list_passthrough() -> None:
    """Projector returns the list as-is for downstream candidate iteration."""
    record = {"tags": ["tag:server", "tag:prod"]}
    assert _tailscale_field_projector(record, "tags") == ["tag:server", "tag:prod"]


def test_tailscale_projector_unknown_field() -> None:
    """Unknown field name ⇒ None (not raised)."""
    assert _tailscale_field_projector({"hostname": "a"}, "totally-unknown") is None


def test_tailscale_record_id_prefers_nodeid() -> None:
    """``nodeId`` is preferred over legacy ``id``."""
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
    assert _record_id(rec) == expected
