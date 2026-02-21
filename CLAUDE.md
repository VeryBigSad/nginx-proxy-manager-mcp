# npm-mcp

MCP server for Nginx Proxy Manager.

## Setup

- Run: `uv run npm-mcp`
- Test: `uv run pytest`
- Env: `NPM_URL`, `NPM_EMAIL`, `NPM_PASSWORD`

## API Coverage (50 tools)

### Covered

**Proxy Hosts**: list, get, create, update, delete, enable, disable
**Redirection Hosts**: list, get, create, update, delete, enable, disable
**Streams**: list, get, create, update, delete, enable, disable
**Dead Hosts (404)**: list, get, create, update, delete, enable, disable
**Certificates**: list, get, create, delete, renew, list_dns_providers, test_http_challenge
**Access Lists**: list, get, create, update, delete
**Users**: list, get, create, update, delete
**Settings**: list, get, update
**Audit Log**: list
**Reports**: get_host_report

### Intentionally Skipped

- Token endpoints (auth handled internally by client)
- User 2FA (interactive flow, not MCP-suitable)
- User password/permissions (security-sensitive)
- User login-as (edge case admin feature)
- Certificate validate/upload (multipart file upload)
- Certificate download (file download)
