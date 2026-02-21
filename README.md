# npm-mcp

MCP server for managing Nginx Proxy Manager (NPM) instances via Claude/AI assistants. **50 tools** covering the full NPM API.

## Installation

```bash
# Install via uvx (recommended)
uvx npm-mcp

# Or install from source
uv sync
uv run npm-mcp
```

## Configuration

Add to your Claude Desktop config (`~/.config/claude/config.json`):

```json
{
  "mcpServers": {
    "nginx-proxy-manager": {
      "command": "uvx",
      "args": ["npm-mcp"],
      "env": {
        "NPM_URL": "http://your-npm-instance:81",
        "NPM_EMAIL": "admin@example.com",
        "NPM_PASSWORD": "your-password"
      }
    }
  }
}
```

## Available Tools (50)

### Proxy Hosts (7 tools)

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `list_proxy_hosts` | List all proxy hosts | — |
| `get_proxy_host` | Get proxy host by ID | `host_id` |
| `create_proxy_host` | Create a new proxy host | `domain_names`, `forward_host`, `forward_port` |
| `update_proxy_host` | Update a proxy host | `host_id` + any fields to change |
| `delete_proxy_host` | Delete a proxy host | `host_id` |
| `enable_proxy_host` | Enable a proxy host | `host_id` |
| `disable_proxy_host` | Disable a proxy host | `host_id` |

Optional create/update params: `forward_scheme`, `certificate_id`, `ssl_forced`, `block_exploits`, `advanced_config`

### Redirection Hosts (7 tools)

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `list_redirection_hosts` | List all redirection hosts | — |
| `get_redirection_host` | Get redirection host by ID | `host_id` |
| `create_redirection_host` | Create HTTP redirect | `domain_names`, `forward_http_code`, `forward_domain_name` |
| `update_redirection_host` | Update a redirection host | `host_id` + any fields to change |
| `delete_redirection_host` | Delete a redirection host | `host_id` |
| `enable_redirection_host` | Enable a redirection host | `host_id` |
| `disable_redirection_host` | Disable a redirection host | `host_id` |

Optional create/update params: `forward_scheme` (auto/http/https), `preserve_path`, `certificate_id`, `ssl_forced`, `block_exploits`, `advanced_config`

### Streams (7 tools)

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `list_streams` | List all TCP/UDP streams | — |
| `get_stream` | Get stream by ID | `stream_id` |
| `create_stream` | Create a TCP/UDP stream proxy | `incoming_port`, `forwarding_host`, `forwarding_port` |
| `update_stream` | Update a stream | `stream_id` + any fields to change |
| `delete_stream` | Delete a stream | `stream_id` |
| `enable_stream` | Enable a stream | `stream_id` |
| `disable_stream` | Disable a stream | `stream_id` |

Optional create/update params: `tcp_forwarding`, `udp_forwarding`, `certificate_id`

### Dead Hosts / 404 Hosts (7 tools)

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `list_dead_hosts` | List all 404 dead hosts | — |
| `get_dead_host` | Get dead host by ID | `host_id` |
| `create_dead_host` | Create a 404 dead host | `domain_names` |
| `update_dead_host` | Update a dead host | `host_id` + any fields to change |
| `delete_dead_host` | Delete a dead host | `host_id` |
| `enable_dead_host` | Enable a dead host | `host_id` |
| `disable_dead_host` | Disable a dead host | `host_id` |

Optional create/update params: `certificate_id`, `ssl_forced`, `hsts_enabled`, `hsts_subdomains`, `http2_support`, `advanced_config`

### SSL Certificates (7 tools)

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `list_certificates` | List all SSL certificates | — |
| `get_certificate` | Get certificate by ID | `certificate_id` |
| `request_certificate` | Request a Let's Encrypt cert | `domain_names`, `nice_name` |
| `delete_certificate` | Delete a certificate | `certificate_id` |
| `renew_certificate` | Renew a Let's Encrypt cert | `certificate_id` |
| `list_dns_providers` | List supported DNS providers | — |
| `test_http_challenge` | Test HTTP-01 ACME reachability | `domains` |

### Access Lists (5 tools)

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `list_access_lists` | List all access lists | — |
| `get_access_list` | Get access list by ID | `access_list_id` |
| `create_access_list` | Create an access list | `name` |
| `update_access_list` | Update an access list | `access_list_id` + any fields to change |
| `delete_access_list` | Delete an access list | `access_list_id` |

Optional create/update params: `satisfy_any`, `pass_auth`

### Users (5 tools)

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `list_users` | List all NPM users | — |
| `get_user` | Get user by ID | `user_id` |
| `create_user` | Create a new user | `name`, `email` |
| `update_user` | Update a user | `user_id` + any fields to change |
| `delete_user` | Delete a user | `user_id` |

Optional create/update params: `nickname`, `roles`, `is_disabled`

### Settings (3 tools)

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `list_settings` | List all NPM settings | — |
| `get_setting` | Get a setting by ID | `setting_id` |
| `update_setting` | Update a setting | `setting_id` |

Optional update params: `value`, `meta`

### Audit Log (1 tool)

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `list_audit_log` | List recent audit log entries | — |

### Reports (1 tool)

| Tool | Description | Required Params |
|------|-------------|-----------------|
| `get_host_report` | Get host count report | — |

## Usage Examples

Once configured, use natural language:

- "List all my proxy hosts"
- "Create a proxy host for example.com pointing to 192.168.1.100:8080"
- "Set up a 301 redirect from old.example.com to new.example.com"
- "Create a TCP stream forwarding port 3306 to my database server"
- "Request a Let's Encrypt certificate for api.example.com"
- "Enable the proxy host with ID 5"
- "Show me the audit log"

## Development

```bash
uv sync --dev
uv run pytest
```

## Requirements

- Python 3.10+
- Nginx Proxy Manager instance
- Valid NPM credentials

## License

MIT
