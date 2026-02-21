# npm-mcp

MCP server for managing Nginx Proxy Manager (NPM) instances via Claude/AI assistants.

## Features

- **Proxy Host Management**: List, create, update, delete proxy hosts
- **SSL Certificates**: List and request Let's Encrypt certificates
- **Access Lists**: Manage basic auth and IP restrictions
- **Auto-authentication**: Handles token refresh automatically

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

## Available Tools

### Proxy Host Management

**list_proxy_hosts**
List all configured proxy hosts.
```
No parameters required.
Returns: JSON array of proxy host objects.
```

**get_proxy_host**
Get details of a specific proxy host.
```
Parameters:
  - host_id (integer): ID of the proxy host
Returns: JSON object with proxy host details.
```

**create_proxy_host**
Create a new proxy host.
```
Parameters:
  - domain_names (array of strings): Domain names for this host
  - forward_host (string): Backend server IP/hostname
  - forward_port (integer): Backend server port
  - forward_scheme (string, optional): "http" or "https" (default: "http")
  - ssl_forced (boolean, optional): Force SSL redirect
  - certificate_id (integer, optional): SSL certificate ID
  - block_exploits (boolean, optional): Enable exploit blocking
  - enabled (boolean, optional): Enable the host
Returns: Created proxy host with ID.
```

**update_proxy_host**
Update an existing proxy host.
```
Parameters:
  - host_id (integer): ID of proxy host to update
  - Any fields from create_proxy_host to update
Returns: Updated proxy host object.
```

**delete_proxy_host**
Delete a proxy host.
```
Parameters:
  - host_id (integer): ID of proxy host to delete
Returns: Success message.
```

### SSL Certificate Management

**list_certificates**
List all SSL certificates.
```
No parameters required.
Returns: JSON array of certificate objects.
```

**request_certificate**
Request a new Let's Encrypt certificate.
```
Parameters:
  - nice_name (string): Human-readable name for the certificate
  - domain_names (array of strings): Domains to include in certificate
  - provider (string): Certificate provider (typically "letsencrypt")
Returns: Created certificate with ID.
```

### Access List Management

**list_access_lists**
List all access lists (basic auth / IP restrictions).
```
No parameters required.
Returns: JSON array of access list objects.
```

**create_access_list**
Create a new access list.
```
Parameters:
  - name (string): Name for the access list
  - items (array): Access control items (usernames/passwords or IPs)
Returns: Created access list with ID.
```

**update_access_list**
Update an existing access list.
```
Parameters:
  - access_list_id (integer): ID of access list to update
  - name (string, optional): New name
  - items (array, optional): Updated access control items
Returns: Updated access list object.
```

**delete_access_list**
Delete an access list.
```
Parameters:
  - access_list_id (integer): ID of access list to delete
Returns: Success message.
```

## Usage Examples

Once configured in Claude Desktop, you can use natural language:

- "List all my proxy hosts"
- "Create a proxy host for example.com pointing to 192.168.1.100:8080"
- "Enable SSL for my example.com proxy host"
- "Request a Let's Encrypt certificate for api.example.com"
- "Delete the proxy host with ID 5"

## Development

```bash
# Install dev dependencies
uv sync --dev

# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=npm_mcp --cov-report=term-missing

# Lint
uv run ruff check .

# Format
uv run ruff format .
```

## Requirements

- Python 3.10+
- Nginx Proxy Manager instance
- Valid NPM credentials

## License

MIT
