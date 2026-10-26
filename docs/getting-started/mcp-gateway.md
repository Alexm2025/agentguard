# MCP gateway

The MCP gateway sits between any MCP client and your MCP servers and works at the JSON-RPC level,
so it is transparent to protocol features it does not need to understand.

## stdio

Replace the server command in your MCP client configuration with AgentGuard wrapping it:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agentguard",
      "args": ["gateway", "mcp-stdio", "--policy", "agentguard.yaml", "--name", "filesystem",
               "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"]
    }
  }
}
```

## Streamable HTTP

```yaml title="gateway.yaml"
auth:
  mode: static
  keys:
    "<sha256 of the key>": { tenant_id: acme }      # agentguard key hash ag_live_...
mcp:
  servers:
    - name: github
      url: https://api.githubcopilot.com/mcp/
      headers: { Authorization: "Bearer ${GITHUB_TOKEN}" }
```

```bash
agentguard gateway mcp-http --config gateway.yaml --port 8100
```

Clients connect to `http://gateway:8100/servers/github/mcp` with an `X-AgentGuard-Key` header.

## What it enforces

| Message | Check |
|---|---|
| `tools/list` result | descriptions scanned for injected instructions; poisoned tools are removed |
| `tools/list` result | each definition is pinned by hash; a changed definition ("rug pull") is quarantined |
| `tools/call` request | evaluated against the policy; blocked calls get an `isError` result explaining why |
| `tools/call` result | recorded as tainted provenance, scanned, and passed, redacted or withheld per policy |

!!! note "The gateway cannot see the user's prompt"
    Without it, every value that came from a tool result counts as untrusted. Clients can pass the
    prompt in `params._meta["agentguard/user_prompt"]` so user-requested values are trusted. For
    stateless (2026-07-28) MCP over HTTP, send `X-AgentGuard-Session` to scope provenance.
