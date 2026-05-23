# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to a 4-axis version scheme parallel to the rest of the
Stallari platform (`major.macro.minor.patch`).

## [0.6.0] - 2026-05-24

### Changed
- DD-338 Phase E.python: depend on `stallari-mcp-helpers>=0.1.0,<1.0.0`; deleted
  local `domain_hint.py` + local `_meta`-envelope helpers (`format_meta_envelope` +
  `append_meta_envelope`) from `formatters.py`. Pure substrate swap for the public
  envelope contract; behavioural shift for the `redactions` field (see below).
- Re-export `meta_envelope` + `append_meta` from `formatters.py` as thin typed
  wrappers around the canonical lib (compensates for `stallari-mcp-helpers v0.1.0`
  shipping without a `py.typed` marker).
- Rename 5 `append_meta_envelope(payload, meta_dict)` call-sites in `server.py`
  to the canonical `meta_envelope(**kwargs)` + `append_meta(payload, envelope)`
  pattern.
- Engine semantics: `compute_domain_hint` is now a Tailscale-specific local
  wrapper in `server.py` that pre-projects each pattern's referenced field
  via `_tailscale_field_projector` and then delegates to
  `stallari_mcp_helpers.compute_domain_hint` (canonical 2-arg). The wrapper
  preserves the 3-arg shape the blade has used since DD-338 A.2.dom.c so
  existing call-sites and tests don't change. The projector continues to
  handle (a) case-insensitive field lookup, (b) `loginName` → `user`
  aliasing across device vs user records, and (c) `nodeId` / `id` fallback
  — none of which the canonical lib's dot-path navigation can express on
  its own.

### Fixed
- **Architect-review correction (post-merge of the original Spec B Cluster
  C flip):** restore `_tailscale_field_projector` and add a local
  `compute_domain_hint` wrapper. The original flip dropped the projector
  and delegated directly to the canonical 2-arg helper — that produced a
  silent behavioural regression for non-lowercase pattern fields,
  `loginName`-only user records, and `nodeId`-only device records. Mirrors
  the pattern landed in `home-assistant-blade-mcp` PR #5. Restored
  `tests/test_domain_hint.py` covering case-insensitive field lookup,
  `loginName` aliasing, `nodeId`/`id` fallback, glob/contains/equals ops,
  and the wrapper's default-projector arg.
- **`_meta.redactions` semantic change.** The local helper allowed `redactions`
  to be a positive integer count of filtered-out records. The canonical lib
  models `redactions` as `list[str]` reason codes (defaulting to `[]`). Tailscale
  call-sites now pass `redactions=[]`; the prior integer count is recoverable
  by the assembler as `matched_total - returned`. Tests assert the recovered
  count rather than the (now empty) `redactions` field.
- Wire-shape: canonical builder alphabetically sorts `filtered_by`. Tailscale's
  `_build_filtered_by` already emits a stable order so the rendered output
  shifts only when the input list contained out-of-order entries (none of the
  Tailscale call-sites do).
