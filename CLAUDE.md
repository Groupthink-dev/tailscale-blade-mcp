# tailscale-blade-mcp

Tailscale network monitoring and security MCP. 17 tools, token-efficient output.

## Architecture

```
src/tailscale_blade_mcp/
├── server.py       — FastMCP server, 17 @mcp.tool decorators
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
- **Credential scrubbing** — 4 regex patterns strip API keys, Bearer tokens from errors
- **No pagination** — Tailscale API returns all results in one response

## API reference

- Base URL: `https://api.tailscale.com/api/v2/`
- Auth: `Authorization: Bearer tskey-api-...`
- Tailnet path: `/tailnet/{tailnet}/...` (use `-` for auto-detect)
- Devices: `/tailnet/-/devices?fields=all`
- Device detail: `/device/{nodeId}?fields=all`

## Testing

Tests are fully mocked — no Tailscale API access required. Fixtures in `tests/conftest.py`.
