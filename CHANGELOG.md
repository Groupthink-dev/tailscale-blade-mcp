# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to a 4-axis version scheme parallel to the rest of the
Stallari platform (`major.macro.minor.patch`).

## [0.8.0] - 2026-06-06

### Fixed (DD-385 Phase 1 — live-hardening campaign)

Two tools were **completely broken against a live tailnet** despite a green
mocked suite — the mock encoded a wrong assumption about the wire shape. Found
by capturing real responses from a live tailnet (the campaign method).

- **`ts_audit_log` returned `400` on every call.** It sent `?count=N`, but the
  Tailscale `logging/configuration` endpoint has no `count` param and **requires**
  an explicit `start` AND `end` RFC3339 window (`400 must specify a "start"/"end"
  query` otherwise). `get_audit_log` now computes a `start`/`end` window, sorts
  entries most-recent-first, and truncates to `count` client-side. New `days`
  tool arg (default 7, max 90) controls the lookback window; wider windows risk
  the 30s API timeout.
- **`ts_webhooks` crashed (`'NoneType' object is not iterable`) on any tailnet
  with no webhooks** — the common case. The live API emits `{"webhooks": null}`
  (not `[]`), so `.get("webhooks", [])` yielded `None`, which then broke the
  tool's `sorted()`. `get_webhooks` now collapses null → `[]` to honour its
  `-> list` contract.

### Changed

- **Audit-log lines now surface the action verb.** Live entries carry both
  `type` (category, e.g. `CONFIG`) and `action` (the verb: `CREATE`/`DELETE`/
  `REVOKE`/`UPDATE`); the formatter showed only the category. Lines now read
  `CONFIG.CREATE` etc., with graceful fallback to whichever field is present.

### Added

- **Live e2e test tier** (`tests/test_e2e.py`, `-m e2e`, opt-in via
  `TAILSCALE_E2E=1`). Locks in the two live-only regressions plus the
  lowest-blast auth-key create→delete loop and the validate-only ACL round-trip.
  ACL **apply** is deliberately *not* exercised here — lockout risk makes
  `ts_acl_set` a throwaway-tailnet-only operation (DD-385 OQ-3; pending DD-382).

### Verified clean (live schema capture, no change needed)

- Device / user / key / settings / DNS / ACL-summary parse shapes all match the
  live wire; ACL `validate` + `If-Match` ETag optimistic-concurrency plumbing
  confirmed against the live API.

## [0.7.0] - 2026-06-03

### Added
- **`ts_acl_set` — ACL apply tool** (P7 7a). Pushes a reviewed full ACL policy
  to the tailnet via `POST /acl`. Write-gated (`TAILSCALE_WRITE_ENABLED=true`).
  Always validates the policy first and refuses to apply on validation failure.
  Optimistic concurrency by default: auto-fetches the current ETag and sends it
  as `If-Match`, so a concurrent admin edit returns a clear "ACL changed since
  you read it — re-fetch" message (HTTP 412) instead of clobbering. Bypass with
  `allow_overwrite_concurrent=true`. On success returns an applied summary (new
  ETag; rule / tagOwner / test counts) plus the DD-338 `_meta` envelope
  (`audit_surface: structured`).
- `client.set_acl(policy, *, if_match=None) -> (applied_policy, new_etag)` and
  `client.get_acl_with_etag() -> (policy, etag)` — header-aware ACL methods that
  surface and consume the policy-file ETag for optimistic concurrency.
- `PreconditionFailedError` (412) and `PolicyError` (400) client exception types
  for actionable ACL-apply error mapping; 403 carries a policy-file-write-scope note.

### Changed
- `client._request` refactored into `_raw_request` (transport + scrubbing, no
  status raising) + `_check_status` so header/status-aware callers can reuse the
  shared error handling. Behaviour of all existing methods is unchanged.
- Version bumped to 0.7.0; `__init__.__version__` re-synced to the package
  version (had drifted to 0.2.0).
- Docs (README + CLAUDE.md) updated: tool count 17 → 19 (the prior "17" was
  already stale — 18 tools shipped before this change), ACL-apply scope
  requirement, optimistic-concurrency behaviour, and `POST /acl` API reference.

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
