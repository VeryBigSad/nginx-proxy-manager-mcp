"""Tests for NPM API client."""

import pytest
from pytest_httpx import HTTPXMock
from npm_mcp.client import NPMClient
from npm_mcp.models import (
    ProxyHost, Certificate, AccessList, NPMConfig,
    RedirectionHost, Stream, DeadHost, User, Setting, AuditLogEntry,
)


@pytest.fixture
def npm_config():
    return NPMConfig(
        url="http://npm.local:81",
        email="admin@example.com",
        password="changeme",
    )


@pytest.fixture
def npm_client(npm_config):
    return NPMClient(npm_config)


@pytest.mark.asyncio
async def test_get_token(httpx_mock: HTTPXMock, npm_client):
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/tokens",
        json={"token": "test_token_123", "expires": "2024-12-31"},
    )

    token = await npm_client._get_token()
    assert token == "test_token_123"
    assert npm_client._token == "test_token_123"


@pytest.mark.asyncio
async def test_list_proxy_hosts(httpx_mock: HTTPXMock, npm_client):
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/tokens",
        json={"token": "test_token"},
    )
    httpx_mock.add_response(
        method="GET",
        url="http://npm.local:81/api/nginx/proxy-hosts",
        json=[
            {
                "id": 1,
                "domain_names": ["example.com"],
                "forward_host": "192.168.1.100",
                "forward_port": 8080,
                "forward_scheme": "http",
                "ssl_forced": False,
                "block_exploits": True,
                "enabled": True,
            }
        ],
    )

    hosts = await npm_client.list_proxy_hosts()
    assert len(hosts) == 1
    assert hosts[0].id == 1
    assert hosts[0].domain_names == ["example.com"]


@pytest.mark.asyncio
async def test_create_proxy_host(httpx_mock: HTTPXMock, npm_client):
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/tokens",
        json={"token": "test_token"},
    )
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/nginx/proxy-hosts",
        json={
            "id": 2,
            "domain_names": ["new.example.com"],
            "forward_host": "192.168.1.200",
            "forward_port": 3000,
            "forward_scheme": "http",
            "ssl_forced": False,
            "block_exploits": True,
            "enabled": True,
        },
    )

    host = ProxyHost(
        domain_names=["new.example.com"],
        forward_host="192.168.1.200",
        forward_port=3000,
    )
    created = await npm_client.create_proxy_host(host)
    assert created.id == 2
    assert created.domain_names == ["new.example.com"]


@pytest.mark.asyncio
async def test_retry_on_401(httpx_mock: HTTPXMock, npm_client):
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/tokens",
        json={"token": "old_token"},
    )
    httpx_mock.add_response(
        method="GET",
        url="http://npm.local:81/api/nginx/proxy-hosts",
        status_code=401,
    )
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/tokens",
        json={"token": "new_token"},
    )
    httpx_mock.add_response(
        method="GET",
        url="http://npm.local:81/api/nginx/proxy-hosts",
        json=[],
    )

    hosts = await npm_client.list_proxy_hosts()
    assert hosts == []
    assert npm_client._token == "new_token"


@pytest.mark.asyncio
async def test_delete_proxy_host(httpx_mock: HTTPXMock, npm_client):
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/tokens",
        json={"token": "test_token"},
    )
    httpx_mock.add_response(
        method="DELETE",
        url="http://npm.local:81/api/nginx/proxy-hosts/1",
        status_code=204,
    )

    await npm_client.delete_proxy_host(1)


@pytest.mark.asyncio
async def test_list_certificates(httpx_mock: HTTPXMock, npm_client):
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/tokens",
        json={"token": "test_token"},
    )
    httpx_mock.add_response(
        method="GET",
        url="http://npm.local:81/api/nginx/certificates",
        json=[
            {
                "id": 1,
                "nice_name": "My Cert",
                "domain_names": ["example.com"],
                "provider": "letsencrypt",
            }
        ],
    )

    certs = await npm_client.list_certificates()
    assert len(certs) == 1
    assert certs[0].nice_name == "My Cert"


@pytest.mark.asyncio
async def test_get_proxy_host(httpx_mock: HTTPXMock, npm_client):
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/tokens",
        json={"token": "test_token"},
    )
    httpx_mock.add_response(
        method="GET",
        url="http://npm.local:81/api/nginx/proxy-hosts/1",
        json={
            "id": 1,
            "domain_names": ["example.com"],
            "forward_host": "192.168.1.100",
            "forward_port": 8080,
            "forward_scheme": "http",
            "ssl_forced": False,
            "block_exploits": True,
            "enabled": True,
        },
    )

    host = await npm_client.get_proxy_host(1)
    assert host.id == 1
    assert host.domain_names == ["example.com"]


@pytest.mark.asyncio
async def test_update_proxy_host(httpx_mock: HTTPXMock, npm_client):
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/tokens",
        json={"token": "test_token"},
    )
    httpx_mock.add_response(
        method="PUT",
        url="http://npm.local:81/api/nginx/proxy-hosts/1",
        json={
            "id": 1,
            "domain_names": ["updated.example.com"],
            "forward_host": "192.168.1.150",
            "forward_port": 9000,
            "forward_scheme": "http",
            "ssl_forced": True,
            "block_exploits": True,
            "enabled": True,
        },
    )

    host = ProxyHost(
        domain_names=["updated.example.com"],
        forward_host="192.168.1.150",
        forward_port=9000,
        ssl_forced=True,
    )
    updated = await npm_client.update_proxy_host(1, host)
    assert updated.id == 1
    assert updated.domain_names == ["updated.example.com"]
    assert updated.ssl_forced is True


@pytest.mark.asyncio
async def test_request_certificate(httpx_mock: HTTPXMock, npm_client):
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/tokens",
        json={"token": "test_token"},
    )
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/nginx/certificates",
        json={
            "id": 1,
            "nice_name": "New Cert",
            "domain_names": ["new.example.com"],
            "provider": "letsencrypt",
        },
    )

    cert = Certificate(
        nice_name="New Cert",
        domain_names=["new.example.com"],
        provider="letsencrypt",
    )
    created = await npm_client.request_certificate(cert)
    assert created.id == 1
    assert created.nice_name == "New Cert"


@pytest.mark.asyncio
async def test_list_access_lists(httpx_mock: HTTPXMock, npm_client):
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/tokens",
        json={"token": "test_token"},
    )
    httpx_mock.add_response(
        method="GET",
        url="http://npm.local:81/api/nginx/access-lists",
        json=[
            {
                "id": 1,
                "name": "Admin Access",
                "items": [{"username": "admin", "password": "secret"}],
            }
        ],
    )

    lists = await npm_client.list_access_lists()
    assert len(lists) == 1
    assert lists[0].name == "Admin Access"


@pytest.mark.asyncio
async def test_create_access_list(httpx_mock: HTTPXMock, npm_client):
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/tokens",
        json={"token": "test_token"},
    )
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/nginx/access-lists",
        json={
            "id": 1,
            "name": "New Access",
            "items": [{"username": "user", "password": "pass"}],
        },
    )

    access_list = AccessList(
        name="New Access",
        items=[{"username": "user", "password": "pass"}],
    )
    created = await npm_client.create_access_list(access_list)
    assert created.id == 1
    assert created.name == "New Access"


@pytest.mark.asyncio
async def test_update_access_list(httpx_mock: HTTPXMock, npm_client):
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/tokens",
        json={"token": "test_token"},
    )
    httpx_mock.add_response(
        method="PUT",
        url="http://npm.local:81/api/nginx/access-lists/1",
        json={
            "id": 1,
            "name": "Updated Access",
            "items": [{"username": "newuser", "password": "newpass"}],
        },
    )

    access_list = AccessList(
        name="Updated Access",
        items=[{"username": "newuser", "password": "newpass"}],
    )
    updated = await npm_client.update_access_list(1, access_list)
    assert updated.id == 1
    assert updated.name == "Updated Access"


@pytest.mark.asyncio
async def test_delete_access_list(httpx_mock: HTTPXMock, npm_client):
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/tokens",
        json={"token": "test_token"},
    )
    httpx_mock.add_response(
        method="DELETE",
        url="http://npm.local:81/api/nginx/access-lists/1",
        status_code=204,
    )

    await npm_client.delete_access_list(1)


@pytest.mark.asyncio
async def test_client_close(npm_client):
    await npm_client.close()


@pytest.mark.asyncio
async def test_token_caching(httpx_mock: HTTPXMock, npm_client):
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/tokens",
        json={"token": "test_token"},
    )

    token1 = await npm_client._get_token()
    token2 = await npm_client._get_token()

    assert token1 == token2 == "test_token"
    assert len(httpx_mock.get_requests()) == 1


_CERT_JSON = {"id": 1, "nice_name": "My Cert", "domain_names": ["example.com"], "provider": "letsencrypt"}
_REDIR_JSON = {"id": 1, "domain_names": ["old.example.com"], "forward_http_code": 301, "forward_domain_name": "new.example.com", "forward_scheme": "auto"}
_STREAM_JSON = {"id": 1, "incoming_port": 8080, "forwarding_host": "192.168.1.100", "forwarding_port": 80}
_DEAD_JSON = {"id": 1, "domain_names": ["dead.example.com"]}
_USER_JSON = {"id": 1, "name": "Admin", "email": "admin@example.com"}
_SETTING_JSON = {"id": "default-site", "value": "congratulations", "name": "Default Site", "description": "What to show on the default site"}
_AUDIT_JSON = {"id": 1, "action": "created", "object_type": "proxy-host", "object_id": 1}


def _tok(httpx_mock):
    httpx_mock.add_response(method="POST", url="http://npm.local:81/api/tokens", json={"token": "test_token"})


@pytest.mark.asyncio
async def test_enable_proxy_host(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="POST", url="http://npm.local:81/api/nginx/proxy-hosts/1/enable", status_code=200)
    await npm_client.enable_proxy_host(1)


@pytest.mark.asyncio
async def test_disable_proxy_host(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="POST", url="http://npm.local:81/api/nginx/proxy-hosts/1/disable", status_code=200)
    await npm_client.disable_proxy_host(1)


@pytest.mark.asyncio
async def test_get_certificate(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="GET", url="http://npm.local:81/api/nginx/certificates/1", json=_CERT_JSON)
    cert = await npm_client.get_certificate(1)
    assert cert.id == 1
    assert cert.nice_name == "My Cert"


@pytest.mark.asyncio
async def test_delete_certificate(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="DELETE", url="http://npm.local:81/api/nginx/certificates/1", status_code=204)
    await npm_client.delete_certificate(1)


@pytest.mark.asyncio
async def test_renew_certificate(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="POST", url="http://npm.local:81/api/nginx/certificates/1/renew", json=_CERT_JSON)
    cert = await npm_client.renew_certificate(1)
    assert cert.id == 1


@pytest.mark.asyncio
async def test_list_dns_providers(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="GET", url="http://npm.local:81/api/nginx/certificates/dns-providers", json=[{"id": "cloudflare", "name": "Cloudflare"}])
    providers = await npm_client.list_dns_providers()
    assert providers == [{"id": "cloudflare", "name": "Cloudflare"}]


@pytest.mark.asyncio
async def test_test_http_challenge(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="POST", url="http://npm.local:81/api/nginx/certificates/test-http", json={"example.com": "ok"})
    result = await npm_client.test_http_challenge(["example.com"])
    assert result == {"example.com": "ok"}


@pytest.mark.asyncio
async def test_get_access_list(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="GET", url="http://npm.local:81/api/nginx/access-lists/1", json={"id": 1, "name": "Admin Access", "items": []})
    al = await npm_client.get_access_list(1)
    assert al.id == 1
    assert al.name == "Admin Access"


@pytest.mark.asyncio
async def test_list_redirection_hosts(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="GET", url="http://npm.local:81/api/nginx/redirection-hosts", json=[_REDIR_JSON])
    hosts = await npm_client.list_redirection_hosts()
    assert len(hosts) == 1
    assert hosts[0].id == 1


@pytest.mark.asyncio
async def test_get_redirection_host(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="GET", url="http://npm.local:81/api/nginx/redirection-hosts/1", json=_REDIR_JSON)
    host = await npm_client.get_redirection_host(1)
    assert host.id == 1


@pytest.mark.asyncio
async def test_create_redirection_host(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="POST", url="http://npm.local:81/api/nginx/redirection-hosts", json=_REDIR_JSON)
    host = RedirectionHost(domain_names=["old.example.com"], forward_http_code=301, forward_domain_name="new.example.com")
    created = await npm_client.create_redirection_host(host)
    assert created.id == 1


@pytest.mark.asyncio
async def test_update_redirection_host(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="PUT", url="http://npm.local:81/api/nginx/redirection-hosts/1", json=_REDIR_JSON)
    host = RedirectionHost(domain_names=["old.example.com"], forward_http_code=301, forward_domain_name="new.example.com")
    updated = await npm_client.update_redirection_host(1, host)
    assert updated.id == 1


@pytest.mark.asyncio
async def test_delete_redirection_host(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="DELETE", url="http://npm.local:81/api/nginx/redirection-hosts/1", status_code=204)
    await npm_client.delete_redirection_host(1)


@pytest.mark.asyncio
async def test_enable_redirection_host(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="POST", url="http://npm.local:81/api/nginx/redirection-hosts/1/enable", status_code=200)
    await npm_client.enable_redirection_host(1)


@pytest.mark.asyncio
async def test_disable_redirection_host(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="POST", url="http://npm.local:81/api/nginx/redirection-hosts/1/disable", status_code=200)
    await npm_client.disable_redirection_host(1)


@pytest.mark.asyncio
async def test_list_streams(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="GET", url="http://npm.local:81/api/nginx/streams", json=[_STREAM_JSON])
    streams = await npm_client.list_streams()
    assert len(streams) == 1
    assert streams[0].id == 1


@pytest.mark.asyncio
async def test_get_stream(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="GET", url="http://npm.local:81/api/nginx/streams/1", json=_STREAM_JSON)
    stream = await npm_client.get_stream(1)
    assert stream.id == 1


@pytest.mark.asyncio
async def test_create_stream(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="POST", url="http://npm.local:81/api/nginx/streams", json=_STREAM_JSON)
    stream = Stream(incoming_port=8080, forwarding_host="192.168.1.100", forwarding_port=80)
    created = await npm_client.create_stream(stream)
    assert created.id == 1


@pytest.mark.asyncio
async def test_update_stream(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="PUT", url="http://npm.local:81/api/nginx/streams/1", json=_STREAM_JSON)
    stream = Stream(incoming_port=8080, forwarding_host="192.168.1.100", forwarding_port=80)
    updated = await npm_client.update_stream(1, stream)
    assert updated.id == 1


@pytest.mark.asyncio
async def test_delete_stream(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="DELETE", url="http://npm.local:81/api/nginx/streams/1", status_code=204)
    await npm_client.delete_stream(1)


@pytest.mark.asyncio
async def test_enable_stream(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="POST", url="http://npm.local:81/api/nginx/streams/1/enable", status_code=200)
    await npm_client.enable_stream(1)


@pytest.mark.asyncio
async def test_disable_stream(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="POST", url="http://npm.local:81/api/nginx/streams/1/disable", status_code=200)
    await npm_client.disable_stream(1)


@pytest.mark.asyncio
async def test_list_dead_hosts(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="GET", url="http://npm.local:81/api/nginx/dead-hosts", json=[_DEAD_JSON])
    hosts = await npm_client.list_dead_hosts()
    assert len(hosts) == 1
    assert hosts[0].id == 1


@pytest.mark.asyncio
async def test_get_dead_host(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="GET", url="http://npm.local:81/api/nginx/dead-hosts/1", json=_DEAD_JSON)
    host = await npm_client.get_dead_host(1)
    assert host.id == 1


@pytest.mark.asyncio
async def test_create_dead_host(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="POST", url="http://npm.local:81/api/nginx/dead-hosts", json=_DEAD_JSON)
    host = DeadHost(domain_names=["dead.example.com"])
    created = await npm_client.create_dead_host(host)
    assert created.id == 1


@pytest.mark.asyncio
async def test_update_dead_host(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="PUT", url="http://npm.local:81/api/nginx/dead-hosts/1", json=_DEAD_JSON)
    host = DeadHost(domain_names=["dead.example.com"])
    updated = await npm_client.update_dead_host(1, host)
    assert updated.id == 1


@pytest.mark.asyncio
async def test_delete_dead_host(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="DELETE", url="http://npm.local:81/api/nginx/dead-hosts/1", status_code=204)
    await npm_client.delete_dead_host(1)


@pytest.mark.asyncio
async def test_enable_dead_host(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="POST", url="http://npm.local:81/api/nginx/dead-hosts/1/enable", status_code=200)
    await npm_client.enable_dead_host(1)


@pytest.mark.asyncio
async def test_disable_dead_host(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="POST", url="http://npm.local:81/api/nginx/dead-hosts/1/disable", status_code=200)
    await npm_client.disable_dead_host(1)


@pytest.mark.asyncio
async def test_list_users(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="GET", url="http://npm.local:81/api/users", json=[_USER_JSON])
    users = await npm_client.list_users()
    assert len(users) == 1
    assert users[0].id == 1


@pytest.mark.asyncio
async def test_get_user(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="GET", url="http://npm.local:81/api/users/1", json=_USER_JSON)
    user = await npm_client.get_user(1)
    assert user.id == 1
    assert user.name == "Admin"


@pytest.mark.asyncio
async def test_create_user(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="POST", url="http://npm.local:81/api/users", json=_USER_JSON)
    user = User(name="Admin", email="admin@example.com")
    created = await npm_client.create_user(user)
    assert created.id == 1


@pytest.mark.asyncio
async def test_update_user(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="PUT", url="http://npm.local:81/api/users/1", json=_USER_JSON)
    user = User(name="Admin", email="admin@example.com")
    updated = await npm_client.update_user(1, user)
    assert updated.id == 1


@pytest.mark.asyncio
async def test_delete_user(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="DELETE", url="http://npm.local:81/api/users/1", status_code=204)
    await npm_client.delete_user(1)


@pytest.mark.asyncio
async def test_list_settings(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="GET", url="http://npm.local:81/api/settings", json=[_SETTING_JSON])
    settings = await npm_client.list_settings()
    assert len(settings) == 1
    assert settings[0].id == "default-site"


@pytest.mark.asyncio
async def test_get_setting(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="GET", url="http://npm.local:81/api/settings/default-site", json=_SETTING_JSON)
    setting = await npm_client.get_setting("default-site")
    assert setting.id == "default-site"
    assert setting.value == "congratulations"


@pytest.mark.asyncio
async def test_update_setting(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="PUT", url="http://npm.local:81/api/settings/default-site", json=_SETTING_JSON)
    setting = Setting(id="default-site", value="congratulations")
    updated = await npm_client.update_setting("default-site", setting)
    assert updated.id == "default-site"


@pytest.mark.asyncio
async def test_list_audit_log(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="GET", url="http://npm.local:81/api/audit-log", json=[_AUDIT_JSON])
    entries = await npm_client.list_audit_log()
    assert len(entries) == 1
    assert entries[0].id == 1
    assert entries[0].action == "created"


@pytest.mark.asyncio
async def test_get_host_report(httpx_mock: HTTPXMock, npm_client):
    _tok(httpx_mock)
    httpx_mock.add_response(method="GET", url="http://npm.local:81/api/reports/hosts", json={"proxy": 2, "redirection": 1, "stream": 0, "dead": 0})
    report = await npm_client.get_host_report()
    assert report["proxy"] == 2
