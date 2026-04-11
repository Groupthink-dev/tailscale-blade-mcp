# tailscale-blade-mcp

An MCP server that gives AI agents structured access to Tailscale tailnets. Built for the [Model Context Protocol](https://modelcontextprotocol.io) with security visibility and token efficiency as first-class design goals.

## Why this exists

Tailscale exposes a clean REST API (v2) for managing devices, ACL policies, DNS, auth keys, users, and audit logs. This MCP wraps it with the guardrails that automated agents need:

- **Security-first tool set** — 17 tools focused on what network security agents actually need: device inventory, key expiry auditing, ACL review, route approval, DNS hygiene. Not a thin wrapper around every endpoint.
- **Token-efficient output** — compact pipe-delimited format. A 20-device tailnet in ~40 tokens per device. Devices flagged with `KEY_EXPIRY_OFF`, `KEY_EXPIRED`, `UPDATE_AVAILABLE`, `UNAUTHORIZED`, `OFFLINE` at a glance.
- **Write-gated mutations** — device authorization, tagging, key management, and route approval require explicit opt-in via `TAILSCALE_WRITE_ENABLED=true`. Destructive operations (delete device, revoke key) additionally require per-call `confirm=true`.
- **SecOps visibility** — ACL policy summary shows groups, rules, SSH rules, and tag owners. Audit log shows who changed what. Key listing flags reusable keys and expiry status.

## How this differs from other Tailscale MCPs

| | tailscale-blade-mcp | HexSleeves/tailscale-mcp | jaxxstorm/tailscale-mcp |
|---|---|---|---|
| **Focus** | Monitoring + security (17 tools) | Management (~15 tools) | Read-only (~5 tools) |
| **Design for** | LLM agents (token-efficient) | Claude Code | General MCP |
| **Output** | Pipe-delimited, compact | Full JSON | Full JSON |
| **Write safety** | Dual-gated (env + confirm) | Direct writes | Read-only |
| **Audit log** | Yes | No | No |
| **ACL summary** | Parsed groups/rules/SSH/tags | Raw JSON | Raw JSON |
| **Key hygiene** | Flags reusable, expiry status | Basic listing | No |
| **Marketplace** | Sidereal certified | Standalone | Standalone |

## Quick start

```bash
# Install
uv pip install -e .

# Configure
export TAILSCALE_API_KEY="tskey-api-..."

# Run
tailscale-blade-mcp
```

## 17 tools, 5 categories

### Info (1 tool)

| Tool | Purpose | Token cost |
|------|---------|------------|
| `ts_info` | Health check — device counts, online/offline, key expiry warnings, settings, write gate | ~100 |

### Devices (3 tools)

| Tool | Purpose | Token cost |
|------|---------|------------|
| `ts_devices` | All devices — hostname, OS, IP, online/offline, key expiry, tags, updates | ~40/device |
| `ts_device` | Full detail — addresses, client version, key status, tags, user | ~120 |
| `ts_device_routes` | Routes — advertised subnets, approved/unapproved status | ~30/route |

### Network (3 tools)

| Tool | Purpose | Token cost |
|------|---------|------------|
| `ts_dns` | DNS — nameservers, MagicDNS, search paths, split DNS | ~50 |
| `ts_acl` | ACL policy — groups, rules, SSH rules, tag owners | ~30/rule |
| `ts_acl_validate` | Validate a policy without applying it | ~20 |

### Users & Keys (3 tools)

| Tool | Purpose | Token cost |
|------|---------|------------|
| `ts_keys` | Auth keys — ID, reusable/ephemeral/preauth flags, tags, expiry | ~25/key |
| `ts_users` | Users — name, role, status, device count, online/last seen | ~25/user |
| `ts_webhooks` | Webhooks — endpoint URL, event subscriptions | ~25/webhook |

### Audit (1 tool)

| Tool | Purpose | Token cost |
|------|---------|------------|
| `ts_audit_log` | Configuration changes — who, what, when | ~25/entry |

### Write Operations (6 tools, gated)

| Tool | Gate | Purpose |
|------|------|---------|
| `ts_authorize_device` | write | Authorize or deauthorize a device |
| `ts_set_tags` | write | Set ACL tags on a device |
| `ts_expire_device` | write | Force key expiry — device must re-authenticate |
| `ts_approve_routes` | write | Approve advertised subnet routes |
| `ts_create_key` | write | Create an auth key (reusable/ephemeral/preauth) |
| `ts_delete_key` | write + confirm | Revoke an auth key permanently |
| `ts_delete_device` | write + confirm | Remove a device from the tailnet |

### Output format

```
macbook | os=mac | ip=100.100.1.1 | online | expires=2026-07-11 | id=n1234567890
nas | os=linux | ip=100.100.1.2 | online | KEY_EXPIRY_OFF | UPDATE_AVAILABLE | tags=server,infra | id=n9876543210
phone | os=iOS | ip=100.100.1.3 | OFFLINE | last=2d ago | expires=2026-05-01 | id=n5555555555
```

## Authentication

Tailscale supports two auth methods:

| Method | Token prefix | Best for |
|--------|-------------|----------|
| **API access token** | `tskey-api-` | Personal use, quick setup |
| **OAuth client** | Bearer token from client_credentials flow | Automation, scoped permissions |

Both are passed via `TAILSCALE_API_KEY`. For OAuth, obtain a Bearer token first and pass that.

## Security model

| Layer | Mechanism |
|-------|-----------|
| **Write gate** | `TAILSCALE_WRITE_ENABLED=true` required for any mutation |
| **Destructive confirm** | `ts_delete_key` and `ts_delete_device` require `confirm=true` |
| **Credential scrubbing** | API keys, Bearer tokens, Authorization headers stripped from errors |
| **Bearer auth** | Optional `TAILSCALE_MCP_API_TOKEN` for HTTP transport |
| **Tailnet auto-detect** | Uses `-` shorthand by default — no tailnet name in config |

## Sidereal integration

```json
{
  "mcpServers": {
    "tailscale": {
      "type": "stdio",
      "command": "uv",
      "args": ["--directory", "~/src/tailscale-blade-mcp", "run", "tailscale-blade-mcp"],
      "env": {
        "TAILSCALE_API_KEY": "tskey-api-...",
        "TAILSCALE_WRITE_ENABLED": "false"
      }
    }
  }
}
```

### Webhook trigger patterns

- **Key expiry approaching** — `ts_devices` flags `KEY_EXPIRY_OFF` and expired keys for proactive rotation
- **Unauthorized devices** — `ts_devices` flags `UNAUTHORIZED` for approval workflows
- **Route approval** — `ts_device_routes` shows unapproved subnets for security review
- **ACL changes** — `ts_audit_log` tracks policy updates for compliance auditing
- **Stale devices** — `ts_devices` shows `OFFLINE` with last-seen time for cleanup workflows

## Development

```bash
make install-dev    # Install with dev + test dependencies
make test           # Unit tests (mocked, no API access needed)
make check          # Lint + format + type-check
make run            # Start MCP server (stdio)
```

### Architecture

```
src/tailscale_blade_mcp/
├── server.py       — FastMCP server, 17 @mcp.tool decorators
├── client.py       — TailscaleClient wrapping httpx async, credential scrubbing
├── formatters.py   — Token-efficient output (pipe-delimited, null omission, human units)
├── models.py       — TailscaleConfig, write gate, constants
└── auth.py         — Bearer token middleware for HTTP transport
```

Built with [FastMCP](https://github.com/jlowin/fastmcp) and [httpx](https://www.python-httpx.org/).

## License

MIT
