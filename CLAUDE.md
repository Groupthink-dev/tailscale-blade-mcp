# tailscale-blade-mcp

Tailscale network monitoring and security MCP. 19 tools, token-efficient output.

## Architecture

```
src/tailscale_blade_mcp/
├── server.py       — FastMCP server, 19 @mcp.tool decorators
├── client.py       — TailscaleClient wrapping httpx async, credential scrubbing
├── formatters.py   — Token-efficient output (pipe-delimited, null omission, relative times)
├── models.py       — TailscaleConfig, write gate
└── auth.py         — BearerAuthMiddleware for HTTP transport
```

## Dev commands

```bash
make install-dev    # Install with dev + test deps
make test           # Unit tests (no API access needed)
make check          # ruff lint + format + mypy
make run            # Start MCP server (stdio)
```

## Key patterns

- **httpx async** — direct REST API calls, no third-party Tailscale library
- **Tailnet `-` shorthand** — auto-detects from API key, no explicit tailnet config needed
- **`nodeId` preferred** — newer device identifier format (not legacy `id`)
- **Write gate** — `TAILSCALE_WRITE_ENABLED=true` required for mutations, destructive ops also need `confirm=true`
- **ACL apply** — `ts_acl_set` validates first, then POSTs with optimistic concurrency: it auto-fetches the current ETag and sends `If-Match` so a concurrent admin edit 412s instead of clobbering (bypass via `allow_overwrite_concurrent=true`). `client.get_acl_with_etag()` surfaces the ETag; `client.set_acl(policy, if_match=...)` returns `(applied_policy, new_etag)`. Apply needs a token with **policy-file write scope** (read-only keys 403).
- **Credential scrubbing** — 4 regex patterns strip API keys, Bearer tokens from errors
- **No pagination** — Tailscale API returns all results in one response

## API reference

- Base URL: `https://api.tailscale.com/api/v2/`
- Auth: `Authorization: Bearer tskey-api-...`
- Tailnet path: `/tailnet/{tailnet}/...` (use `-` for auto-detect)
- Devices: `/tailnet/-/devices?fields=all`
- Device detail: `/device/{nodeId}?fields=all`
- ACL read: `GET /tailnet/-/acl` (response carries `ETag`)
- ACL validate: `POST /tailnet/-/acl/validate`
- ACL apply: `POST /tailnet/-/acl` (`Content-Type: application/json`, optional `If-Match: <etag>`; needs policy-file write scope)

## Testing

Tests are fully mocked — no Tailscale API access required. Fixtures in `tests/conftest.py`.
