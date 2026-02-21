"""Tests for MCP server."""

import pytest
from unittest.mock import AsyncMock, patch
from mcp.types import TextContent
from npm_mcp.server import call_tool, list_tools, app
from npm_mcp.models import (
    ProxyHost, Certificate, AccessList, RedirectionHost,
    Stream, DeadHost, User, Setting, AuditLogEntry,
)


@pytest.mark.asyncio
async def test_list_tools():
    tools = await list_tools()
    tool_names = [t.name for t in tools]

    assert "list_proxy_hosts" in tool_names
    assert "get_proxy_host" in tool_names
    assert "create_proxy_host" in tool_names
    assert "update_proxy_host" in tool_names
    assert "delete_proxy_host" in tool_names
    assert "enable_proxy_host" in tool_names
    assert "disable_proxy_host" in tool_names
    assert "list_redirection_hosts" in tool_names
    assert "get_redirection_host" in tool_names
    assert "create_redirection_host" in tool_names
    assert "update_redirection_host" in tool_names
    assert "delete_redirection_host" in tool_names
    assert "enable_redirection_host" in tool_names
    assert "disable_redirection_host" in tool_names
    assert "list_streams" in tool_names
    assert "get_stream" in tool_names
    assert "create_stream" in tool_names
    assert "update_stream" in tool_names
    assert "delete_stream" in tool_names
    assert "enable_stream" in tool_names
    assert "disable_stream" in tool_names
    assert "list_dead_hosts" in tool_names
    assert "get_dead_host" in tool_names
    assert "create_dead_host" in tool_names
    assert "update_dead_host" in tool_names
    assert "delete_dead_host" in tool_names
    assert "enable_dead_host" in tool_names
    assert "disable_dead_host" in tool_names
    assert "list_certificates" in tool_names
    assert "get_certificate" in tool_names
    assert "request_certificate" in tool_names
    assert "delete_certificate" in tool_names
    assert "renew_certificate" in tool_names
    assert "list_dns_providers" in tool_names
    assert "test_http_challenge" in tool_names
    assert "list_access_lists" in tool_names
    assert "get_access_list" in tool_names
    assert "create_access_list" in tool_names
    assert "update_access_list" in tool_names
    assert "delete_access_list" in tool_names
    assert "list_users" in tool_names
    assert "get_user" in tool_names
    assert "create_user" in tool_names
    assert "update_user" in tool_names
    assert "delete_user" in tool_names
    assert "list_settings" in tool_names
    assert "get_setting" in tool_names
    assert "update_setting" in tool_names
    assert "list_audit_log" in tool_names
    assert "get_host_report" in tool_names


@pytest.mark.asyncio
async def test_list_proxy_hosts_tool():
    mock_client = AsyncMock()
    mock_client.list_proxy_hosts.return_value = [
        ProxyHost(
            id=1,
            domain_names=["example.com"],
            forward_host="192.168.1.100",
            forward_port=8080,
        )
    ]

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("list_proxy_hosts", {})

    assert len(result) == 1
    assert isinstance(result[0], TextContent)
    assert "example.com" in result[0].text


@pytest.mark.asyncio
async def test_get_proxy_host_tool():
    mock_client = AsyncMock()
    mock_client.get_proxy_host.return_value = ProxyHost(
        id=1,
        domain_names=["example.com"],
        forward_host="192.168.1.100",
        forward_port=8080,
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("get_proxy_host", {"host_id": 1})

    assert len(result) == 1
    assert "example.com" in result[0].text
    mock_client.get_proxy_host.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_create_proxy_host_tool():
    mock_client = AsyncMock()
    mock_client.create_proxy_host.return_value = ProxyHost(
        id=2,
        domain_names=["new.example.com"],
        forward_host="192.168.1.200",
        forward_port=3000,
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool(
            "create_proxy_host",
            {
                "domain_names": ["new.example.com"],
                "forward_host": "192.168.1.200",
                "forward_port": 3000,
            },
        )

    assert len(result) == 1
    assert "new.example.com" in result[0].text


@pytest.mark.asyncio
async def test_update_proxy_host_tool():
    mock_client = AsyncMock()
    mock_client.get_proxy_host.return_value = ProxyHost(
        id=1,
        domain_names=["example.com"],
        forward_host="192.168.1.100",
        forward_port=8080,
    )
    mock_client.update_proxy_host.return_value = ProxyHost(
        id=1,
        domain_names=["updated.example.com"],
        forward_host="192.168.1.100",
        forward_port=9090,
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool(
            "update_proxy_host",
            {
                "host_id": 1,
                "domain_names": ["updated.example.com"],
                "forward_port": 9090,
            },
        )

    assert len(result) == 1
    assert "updated.example.com" in result[0].text
    mock_client.get_proxy_host.assert_called_once_with(1)
    mock_client.update_proxy_host.assert_called_once()


@pytest.mark.asyncio
async def test_delete_proxy_host_tool():
    mock_client = AsyncMock()
    mock_client.delete_proxy_host.return_value = None

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("delete_proxy_host", {"host_id": 1})

    assert len(result) == 1
    assert "deleted successfully" in result[0].text
    mock_client.delete_proxy_host.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_enable_proxy_host_tool():
    mock_client = AsyncMock()
    mock_client.enable_proxy_host.return_value = None

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("enable_proxy_host", {"host_id": 1})

    assert len(result) == 1
    assert "enabled successfully" in result[0].text
    mock_client.enable_proxy_host.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_disable_proxy_host_tool():
    mock_client = AsyncMock()
    mock_client.disable_proxy_host.return_value = None

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("disable_proxy_host", {"host_id": 1})

    assert len(result) == 1
    assert "disabled successfully" in result[0].text
    mock_client.disable_proxy_host.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_list_redirection_hosts_tool():
    mock_client = AsyncMock()
    mock_client.list_redirection_hosts.return_value = [
        RedirectionHost(
            domain_names=["old.example.com"],
            forward_http_code=301,
            forward_domain_name="new.example.com",
        )
    ]

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("list_redirection_hosts", {})

    assert len(result) == 1
    assert "old.example.com" in result[0].text


@pytest.mark.asyncio
async def test_get_redirection_host_tool():
    mock_client = AsyncMock()
    mock_client.get_redirection_host.return_value = RedirectionHost(
        id=1,
        domain_names=["old.example.com"],
        forward_http_code=301,
        forward_domain_name="new.example.com",
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("get_redirection_host", {"host_id": 1})

    assert len(result) == 1
    assert "old.example.com" in result[0].text
    mock_client.get_redirection_host.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_create_redirection_host_tool():
    mock_client = AsyncMock()
    mock_client.create_redirection_host.return_value = RedirectionHost(
        id=2,
        domain_names=["old.example.com"],
        forward_http_code=301,
        forward_domain_name="new.example.com",
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool(
            "create_redirection_host",
            {
                "domain_names": ["old.example.com"],
                "forward_http_code": 301,
                "forward_domain_name": "new.example.com",
            },
        )

    assert len(result) == 1
    assert "old.example.com" in result[0].text


@pytest.mark.asyncio
async def test_update_redirection_host_tool():
    mock_client = AsyncMock()
    mock_client.get_redirection_host.return_value = RedirectionHost(
        id=1,
        domain_names=["old.example.com"],
        forward_http_code=301,
        forward_domain_name="new.example.com",
    )
    mock_client.update_redirection_host.return_value = RedirectionHost(
        id=1,
        domain_names=["old.example.com"],
        forward_http_code=302,
        forward_domain_name="updated.example.com",
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool(
            "update_redirection_host",
            {"host_id": 1, "forward_domain_name": "updated.example.com", "forward_http_code": 302},
        )

    assert len(result) == 1
    assert "updated.example.com" in result[0].text
    mock_client.get_redirection_host.assert_called_once_with(1)
    mock_client.update_redirection_host.assert_called_once()


@pytest.mark.asyncio
async def test_delete_redirection_host_tool():
    mock_client = AsyncMock()
    mock_client.delete_redirection_host.return_value = None

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("delete_redirection_host", {"host_id": 1})

    assert len(result) == 1
    assert "deleted successfully" in result[0].text
    mock_client.delete_redirection_host.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_enable_redirection_host_tool():
    mock_client = AsyncMock()
    mock_client.enable_redirection_host.return_value = None

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("enable_redirection_host", {"host_id": 1})

    assert len(result) == 1
    assert "enabled successfully" in result[0].text
    mock_client.enable_redirection_host.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_disable_redirection_host_tool():
    mock_client = AsyncMock()
    mock_client.disable_redirection_host.return_value = None

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("disable_redirection_host", {"host_id": 1})

    assert len(result) == 1
    assert "disabled successfully" in result[0].text
    mock_client.disable_redirection_host.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_list_streams_tool():
    mock_client = AsyncMock()
    mock_client.list_streams.return_value = [
        Stream(incoming_port=8080, forwarding_host="192.168.1.100", forwarding_port=80)
    ]

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("list_streams", {})

    assert len(result) == 1
    assert "192.168.1.100" in result[0].text


@pytest.mark.asyncio
async def test_get_stream_tool():
    mock_client = AsyncMock()
    mock_client.get_stream.return_value = Stream(
        id=1, incoming_port=8080, forwarding_host="192.168.1.100", forwarding_port=80
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("get_stream", {"stream_id": 1})

    assert len(result) == 1
    assert "192.168.1.100" in result[0].text
    mock_client.get_stream.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_create_stream_tool():
    mock_client = AsyncMock()
    mock_client.create_stream.return_value = Stream(
        id=2, incoming_port=9090, forwarding_host="192.168.1.200", forwarding_port=80
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool(
            "create_stream",
            {
                "incoming_port": 9090,
                "forwarding_host": "192.168.1.200",
                "forwarding_port": 80,
            },
        )

    assert len(result) == 1
    assert "192.168.1.200" in result[0].text


@pytest.mark.asyncio
async def test_update_stream_tool():
    mock_client = AsyncMock()
    mock_client.get_stream.return_value = Stream(
        id=1, incoming_port=8080, forwarding_host="192.168.1.100", forwarding_port=80
    )
    mock_client.update_stream.return_value = Stream(
        id=1, incoming_port=8080, forwarding_host="192.168.1.100", forwarding_port=9999
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("update_stream", {"stream_id": 1, "forwarding_port": 9999})

    assert len(result) == 1
    assert "9999" in result[0].text
    mock_client.get_stream.assert_called_once_with(1)
    mock_client.update_stream.assert_called_once()


@pytest.mark.asyncio
async def test_delete_stream_tool():
    mock_client = AsyncMock()
    mock_client.delete_stream.return_value = None

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("delete_stream", {"stream_id": 1})

    assert len(result) == 1
    assert "deleted successfully" in result[0].text
    mock_client.delete_stream.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_enable_stream_tool():
    mock_client = AsyncMock()
    mock_client.enable_stream.return_value = None

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("enable_stream", {"stream_id": 1})

    assert len(result) == 1
    assert "enabled successfully" in result[0].text
    mock_client.enable_stream.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_disable_stream_tool():
    mock_client = AsyncMock()
    mock_client.disable_stream.return_value = None

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("disable_stream", {"stream_id": 1})

    assert len(result) == 1
    assert "disabled successfully" in result[0].text
    mock_client.disable_stream.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_list_dead_hosts_tool():
    mock_client = AsyncMock()
    mock_client.list_dead_hosts.return_value = [
        DeadHost(domain_names=["dead.example.com"])
    ]

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("list_dead_hosts", {})

    assert len(result) == 1
    assert "dead.example.com" in result[0].text


@pytest.mark.asyncio
async def test_get_dead_host_tool():
    mock_client = AsyncMock()
    mock_client.get_dead_host.return_value = DeadHost(
        id=1, domain_names=["dead.example.com"]
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("get_dead_host", {"host_id": 1})

    assert len(result) == 1
    assert "dead.example.com" in result[0].text
    mock_client.get_dead_host.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_create_dead_host_tool():
    mock_client = AsyncMock()
    mock_client.create_dead_host.return_value = DeadHost(
        id=2, domain_names=["dead.example.com"]
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool(
            "create_dead_host", {"domain_names": ["dead.example.com"]}
        )

    assert len(result) == 1
    assert "dead.example.com" in result[0].text


@pytest.mark.asyncio
async def test_update_dead_host_tool():
    mock_client = AsyncMock()
    mock_client.get_dead_host.return_value = DeadHost(
        id=1, domain_names=["dead.example.com"]
    )
    mock_client.update_dead_host.return_value = DeadHost(
        id=1, domain_names=["updated-dead.example.com"]
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool(
            "update_dead_host",
            {"host_id": 1, "domain_names": ["updated-dead.example.com"]},
        )

    assert len(result) == 1
    assert "updated-dead.example.com" in result[0].text
    mock_client.get_dead_host.assert_called_once_with(1)
    mock_client.update_dead_host.assert_called_once()


@pytest.mark.asyncio
async def test_delete_dead_host_tool():
    mock_client = AsyncMock()
    mock_client.delete_dead_host.return_value = None

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("delete_dead_host", {"host_id": 1})

    assert len(result) == 1
    assert "deleted successfully" in result[0].text
    mock_client.delete_dead_host.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_enable_dead_host_tool():
    mock_client = AsyncMock()
    mock_client.enable_dead_host.return_value = None

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("enable_dead_host", {"host_id": 1})

    assert len(result) == 1
    assert "enabled successfully" in result[0].text
    mock_client.enable_dead_host.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_disable_dead_host_tool():
    mock_client = AsyncMock()
    mock_client.disable_dead_host.return_value = None

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("disable_dead_host", {"host_id": 1})

    assert len(result) == 1
    assert "disabled successfully" in result[0].text
    mock_client.disable_dead_host.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_list_certificates_tool():
    mock_client = AsyncMock()
    mock_client.list_certificates.return_value = [
        Certificate(
            id=1, nice_name="My Cert", domain_names=["example.com"], provider="letsencrypt"
        )
    ]

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("list_certificates", {})

    assert len(result) == 1
    assert "My Cert" in result[0].text


@pytest.mark.asyncio
async def test_get_certificate_tool():
    mock_client = AsyncMock()
    mock_client.get_certificate.return_value = Certificate(
        id=1, nice_name="My Cert", domain_names=["example.com"]
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("get_certificate", {"certificate_id": 1})

    assert len(result) == 1
    assert "My Cert" in result[0].text
    mock_client.get_certificate.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_request_certificate_tool():
    mock_client = AsyncMock()
    mock_client.request_certificate.return_value = Certificate(
        id=1, nice_name="New Cert", domain_names=["new.example.com"], provider="letsencrypt"
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool(
            "request_certificate",
            {
                "nice_name": "New Cert",
                "domain_names": ["new.example.com"],
                "provider": "letsencrypt",
            },
        )

    assert len(result) == 1
    assert "New Cert" in result[0].text


@pytest.mark.asyncio
async def test_delete_certificate_tool():
    mock_client = AsyncMock()
    mock_client.delete_certificate.return_value = None

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("delete_certificate", {"certificate_id": 1})

    assert len(result) == 1
    assert "deleted successfully" in result[0].text
    mock_client.delete_certificate.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_renew_certificate_tool():
    mock_client = AsyncMock()
    mock_client.renew_certificate.return_value = Certificate(
        id=1, nice_name="My Cert", domain_names=["example.com"]
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("renew_certificate", {"certificate_id": 1})

    assert len(result) == 1
    assert "My Cert" in result[0].text
    mock_client.renew_certificate.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_list_dns_providers_tool():
    mock_client = AsyncMock()
    mock_client.list_dns_providers.return_value = [{"id": "cloudflare", "name": "Cloudflare"}]

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("list_dns_providers", {})

    assert len(result) == 1
    assert "cloudflare" in result[0].text


@pytest.mark.asyncio
async def test_test_http_challenge_tool():
    mock_client = AsyncMock()
    mock_client.test_http_challenge.return_value = {"example.com": "ok"}

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("test_http_challenge", {"domains": ["example.com"]})

    assert len(result) == 1
    assert "example.com" in result[0].text
    mock_client.test_http_challenge.assert_called_once_with(["example.com"])


@pytest.mark.asyncio
async def test_list_access_lists_tool():
    mock_client = AsyncMock()
    mock_client.list_access_lists.return_value = [
        AccessList(id=1, name="Admin Access", items=[{"username": "admin"}])
    ]

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("list_access_lists", {})

    assert len(result) == 1
    assert "Admin Access" in result[0].text


@pytest.mark.asyncio
async def test_get_access_list_tool():
    mock_client = AsyncMock()
    mock_client.get_access_list.return_value = AccessList(
        id=1, name="Admin Access", items=[{"username": "admin"}]
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("get_access_list", {"access_list_id": 1})

    assert len(result) == 1
    assert "Admin Access" in result[0].text
    mock_client.get_access_list.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_create_access_list_tool():
    mock_client = AsyncMock()
    mock_client.create_access_list.return_value = AccessList(
        id=2, name="New Access", items=[{"username": "newuser"}]
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool(
            "create_access_list",
            {"name": "New Access", "items": [{"username": "newuser"}]},
        )

    assert len(result) == 1
    assert "New Access" in result[0].text


@pytest.mark.asyncio
async def test_update_access_list_tool():
    mock_client = AsyncMock()
    mock_client.get_access_list.return_value = AccessList(
        id=1, name="Old Access", items=[{"username": "olduser"}]
    )
    mock_client.update_access_list.return_value = AccessList(
        id=1, name="Updated Access", items=[{"username": "updateduser"}]
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool(
            "update_access_list",
            {"access_list_id": 1, "name": "Updated Access"},
        )

    assert len(result) == 1
    assert "Updated Access" in result[0].text
    mock_client.get_access_list.assert_called_once_with(1)
    mock_client.update_access_list.assert_called_once()


@pytest.mark.asyncio
async def test_delete_access_list_tool():
    mock_client = AsyncMock()
    mock_client.delete_access_list.return_value = None

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("delete_access_list", {"access_list_id": 1})

    assert len(result) == 1
    assert "deleted successfully" in result[0].text


@pytest.mark.asyncio
async def test_list_users_tool():
    mock_client = AsyncMock()
    mock_client.list_users.return_value = [
        User(name="Test User", email="test@example.com")
    ]

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("list_users", {})

    assert len(result) == 1
    assert "Test User" in result[0].text


@pytest.mark.asyncio
async def test_get_user_tool():
    mock_client = AsyncMock()
    mock_client.get_user.return_value = User(
        id=1, name="Test User", email="test@example.com"
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("get_user", {"user_id": 1})

    assert len(result) == 1
    assert "Test User" in result[0].text
    mock_client.get_user.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_create_user_tool():
    mock_client = AsyncMock()
    mock_client.create_user.return_value = User(
        id=2, name="New User", email="new@example.com"
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool(
            "create_user",
            {"name": "New User", "email": "new@example.com"},
        )

    assert len(result) == 1
    assert "New User" in result[0].text


@pytest.mark.asyncio
async def test_update_user_tool():
    mock_client = AsyncMock()
    mock_client.get_user.return_value = User(
        id=1, name="Test User", email="test@example.com"
    )
    mock_client.update_user.return_value = User(
        id=1, name="Updated User", email="test@example.com"
    )

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("update_user", {"user_id": 1, "name": "Updated User"})

    assert len(result) == 1
    assert "Updated User" in result[0].text
    mock_client.get_user.assert_called_once_with(1)
    mock_client.update_user.assert_called_once()


@pytest.mark.asyncio
async def test_delete_user_tool():
    mock_client = AsyncMock()
    mock_client.delete_user.return_value = None

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("delete_user", {"user_id": 1})

    assert len(result) == 1
    assert "deleted successfully" in result[0].text
    mock_client.delete_user.assert_called_once_with(1)


@pytest.mark.asyncio
async def test_list_settings_tool():
    mock_client = AsyncMock()
    mock_client.list_settings.return_value = [
        Setting(id="default-site", value="congratulations")
    ]

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("list_settings", {})

    assert len(result) == 1
    assert "default-site" in result[0].text


@pytest.mark.asyncio
async def test_get_setting_tool():
    mock_client = AsyncMock()
    mock_client.get_setting.return_value = Setting(id="default-site", value="congratulations")

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("get_setting", {"setting_id": "default-site"})

    assert len(result) == 1
    assert "default-site" in result[0].text
    mock_client.get_setting.assert_called_once_with("default-site")


@pytest.mark.asyncio
async def test_update_setting_tool():
    mock_client = AsyncMock()
    mock_client.get_setting.return_value = Setting(id="default-site", value="congratulations")
    mock_client.update_setting.return_value = Setting(id="default-site", value="404")

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("update_setting", {"setting_id": "default-site", "value": "404"})

    assert len(result) == 1
    assert "default-site" in result[0].text
    mock_client.get_setting.assert_called_once_with("default-site")
    mock_client.update_setting.assert_called_once()


@pytest.mark.asyncio
async def test_list_audit_log_tool():
    mock_client = AsyncMock()
    mock_client.list_audit_log.return_value = [
        AuditLogEntry(id=1, action="created", object_type="proxy-host")
    ]

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("list_audit_log", {})

    assert len(result) == 1
    assert "created" in result[0].text


@pytest.mark.asyncio
async def test_get_host_report_tool():
    mock_client = AsyncMock()
    mock_client.get_host_report.return_value = {"proxy": 5, "redirection": 3, "stream": 1, "dead": 0}

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("get_host_report", {})

    assert len(result) == 1
    assert "proxy" in result[0].text
    mock_client.get_host_report.assert_called_once()


@pytest.mark.asyncio
async def test_unknown_tool():
    with patch("npm_mcp.server.npm_client", AsyncMock()):
        result = await call_tool("unknown_tool", {})

    assert len(result) == 1
    assert "Unknown tool" in result[0].text


@pytest.mark.asyncio
async def test_tool_error_handling():
    mock_client = AsyncMock()
    mock_client.list_proxy_hosts.side_effect = Exception("Network error")

    with patch("npm_mcp.server.npm_client", mock_client):
        result = await call_tool("list_proxy_hosts", {})

    assert len(result) == 1
    assert "Error:" in result[0].text
    assert "Network error" in result[0].text
