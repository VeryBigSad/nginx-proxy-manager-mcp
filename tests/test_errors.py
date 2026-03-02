"""Tests for error handling and validation."""

import pytest
from unittest.mock import AsyncMock
from pytest_httpx import HTTPXMock
from npm_mcp.client import (
    NPMClient,
    NPMClientError,
    NPMConfigError,
    NPMAuthenticationError,
    NPMNetworkError,
    _validate_int_id,
    _validate_setting_id,
    create_client_from_env,
)
from npm_mcp.models import NPMConfig


def test_config_validation_missing_url():
    with pytest.raises(NPMConfigError, match="NPM_URL is required"):
        NPMClient(NPMConfig(url="", email="admin@example.com", password="secret"))


def test_config_validation_missing_email():
    with pytest.raises(NPMConfigError, match="NPM_EMAIL is required"):
        NPMClient(NPMConfig(url="http://npm.local", email="", password="secret"))


def test_config_validation_missing_password():
    with pytest.raises(NPMConfigError, match="NPM_PASSWORD is required"):
        NPMClient(NPMConfig(url="http://npm.local", email="admin@example.com", password=""))


@pytest.mark.asyncio
async def test_authentication_error(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/tokens",
        status_code=401,
        json={"error": "Invalid credentials"},
    )

    client = NPMClient(
        NPMConfig(url="http://npm.local:81", email="wrong@email.com", password="wrongpass")
    )

    with pytest.raises(NPMAuthenticationError, match="Authentication failed"):
        await client._get_token()


@pytest.mark.asyncio
async def test_http_error_on_token_request(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST",
        url="http://npm.local:81/api/tokens",
        status_code=503,
        text="Service Unavailable",
    )

    client = NPMClient(
        NPMConfig(url="http://npm.local:81", email="admin@example.com", password="changeme")
    )

    with pytest.raises(NPMNetworkError, match="HTTP error 503"):
        await client._get_token()


@pytest.mark.asyncio
async def test_network_error_connection_refused(httpx_mock: HTTPXMock):
    httpx_mock.add_exception(Exception("Connection refused"))

    client = NPMClient(
        NPMConfig(url="http://npm.local:81", email="admin@example.com", password="changeme")
    )

    with pytest.raises(NPMNetworkError, match="Unexpected error"):
        await client._get_token()


@pytest.mark.asyncio
async def test_http_error_on_api_call(httpx_mock: HTTPXMock):
    httpx_mock.add_response(
        method="POST", url="http://npm.local:81/api/tokens", json={"token": "test_token"}
    )
    httpx_mock.add_response(
        method="GET",
        url="http://npm.local:81/api/nginx/proxy-hosts",
        status_code=500,
        text="Internal Server Error",
    )

    client = NPMClient(
        NPMConfig(url="http://npm.local:81", email="admin@example.com", password="changeme")
    )

    with pytest.raises(NPMNetworkError, match="HTTP 500 error"):
        await client.list_proxy_hosts()


@pytest.mark.asyncio
async def test_env_client_creation(monkeypatch):
    monkeypatch.setenv("NPM_URL", "http://npm.local:81")
    monkeypatch.setenv("NPM_EMAIL", "admin@example.com")
    monkeypatch.setenv("NPM_PASSWORD", "changeme")

    client = create_client_from_env()
    assert client.config.url == "http://npm.local:81"
    assert client.config.email == "admin@example.com"
    assert client.config.password.get_secret_value() == "changeme"


@pytest.mark.asyncio
async def test_env_client_missing_config(monkeypatch):
    monkeypatch.delenv("NPM_URL", raising=False)
    monkeypatch.delenv("NPM_EMAIL", raising=False)
    monkeypatch.delenv("NPM_PASSWORD", raising=False)

    with pytest.raises(NPMConfigError, match="NPM_URL is required"):
        create_client_from_env()


@pytest.mark.asyncio
async def test_network_error_connect_error(httpx_mock: HTTPXMock):
    import httpx

    httpx_mock.add_exception(httpx.ConnectError("Connection refused"))

    client = NPMClient(
        NPMConfig(url="http://npm.local:81", email="admin@example.com", password="changeme")
    )

    with pytest.raises(NPMNetworkError, match="Cannot connect to NPM"):
        await client._get_token()


@pytest.mark.asyncio
async def test_network_error_timeout(httpx_mock: HTTPXMock):
    import httpx

    httpx_mock.add_exception(httpx.TimeoutException("Request timed out"))

    client = NPMClient(
        NPMConfig(url="http://npm.local:81", email="admin@example.com", password="changeme")
    )

    with pytest.raises(NPMNetworkError, match="Request to NPM timed out"):
        await client._get_token()


@pytest.mark.asyncio
async def test_request_connect_error(httpx_mock: HTTPXMock):
    import httpx

    httpx_mock.add_response(
        method="POST", url="http://npm.local:81/api/tokens", json={"token": "test_token"}
    )
    httpx_mock.add_exception(httpx.ConnectError("Connection refused"), url="http://npm.local:81/api/nginx/proxy-hosts")

    client = NPMClient(
        NPMConfig(url="http://npm.local:81", email="admin@example.com", password="changeme")
    )

    with pytest.raises(NPMNetworkError, match="Cannot connect to NPM"):
        await client.list_proxy_hosts()


@pytest.mark.asyncio
async def test_request_timeout_error(httpx_mock: HTTPXMock):
    import httpx

    httpx_mock.add_response(
        method="POST", url="http://npm.local:81/api/tokens", json={"token": "test_token"}
    )
    httpx_mock.add_exception(httpx.TimeoutException("Request timed out"), url="http://npm.local:81/api/nginx/proxy-hosts")

    client = NPMClient(
        NPMConfig(url="http://npm.local:81", email="admin@example.com", password="changeme")
    )

    with pytest.raises(NPMNetworkError, match="Request to NPM timed out"):
        await client.list_proxy_hosts()


def test_validate_int_id_type_error():
    with pytest.raises(ValueError, match="must be a positive integer"):
        _validate_int_id("abc", "host_id")


def test_validate_int_id_none():
    with pytest.raises(ValueError, match="must be a positive integer"):
        _validate_int_id(None, "host_id")


def test_validate_int_id_zero():
    with pytest.raises(ValueError, match="must be >= 1"):
        _validate_int_id(0, "host_id")


def test_validate_int_id_negative():
    with pytest.raises(ValueError, match="must be >= 1"):
        _validate_int_id(-5, "host_id")


def test_validate_setting_id_invalid():
    with pytest.raises(ValueError, match="setting_id must match"):
        _validate_setting_id("INVALID!")


@pytest.mark.asyncio
async def test_get_token_reraises_npm_client_error():
    client = NPMClient(
        NPMConfig(url="http://npm.local:81", email="admin@example.com", password="changeme")
    )
    client._client.post = AsyncMock(side_effect=NPMClientError("custom error"))

    with pytest.raises(NPMClientError, match="custom error"):
        await client._get_token()


@pytest.mark.asyncio
async def test_request_reraises_npm_client_error():
    client = NPMClient(
        NPMConfig(url="http://npm.local:81", email="admin@example.com", password="changeme")
    )
    client._get_token = AsyncMock(side_effect=NPMAuthenticationError("auth failed"))

    with pytest.raises(NPMAuthenticationError, match="auth failed"):
        await client.list_proxy_hosts()
