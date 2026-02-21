"""Tests for data models."""

import pytest
from npm_mcp.models import (
    ProxyHost, Certificate, AccessList, NPMConfig,
    RedirectionHost, Stream, DeadHost, User, Setting, AuditLogEntry,
)


def test_proxy_host_minimal():
    host = ProxyHost(
        domain_names=["example.com"],
        forward_host="192.168.1.100",
        forward_port=8080,
    )
    assert host.domain_names == ["example.com"]
    assert host.forward_host == "192.168.1.100"
    assert host.forward_port == 8080
    assert host.forward_scheme == "http"
    assert host.ssl_forced is False


def test_proxy_host_with_ssl():
    host = ProxyHost(
        domain_names=["secure.example.com"],
        forward_host="192.168.1.100",
        forward_port=8443,
        forward_scheme="https",
        certificate_id=1,
        ssl_forced=True,
    )
    assert host.certificate_id == 1
    assert host.ssl_forced is True
    assert host.forward_scheme == "https"


def test_certificate_minimal():
    cert = Certificate(
        nice_name="My Certificate",
        domain_names=["example.com", "www.example.com"],
    )
    assert cert.nice_name == "My Certificate"
    assert len(cert.domain_names) == 2
    assert cert.provider == "letsencrypt"


def test_access_list_minimal():
    al = AccessList(name="My Access List")
    assert al.name == "My Access List"
    assert al.satisfy_any is False
    assert al.pass_auth is True


def test_npm_config():
    config = NPMConfig(
        url="http://npm.local:81",
        email="admin@example.com",
        password="secret123",
    )
    assert config.url == "http://npm.local:81"
    assert config.email == "admin@example.com"
    assert config.password.get_secret_value() == "secret123"


def test_redirection_host_minimal():
    host = RedirectionHost(
        domain_names=["ex.com"],
        forward_http_code=301,
        forward_domain_name="new.ex.com",
    )
    assert host.forward_scheme == "auto"
    assert host.preserve_path is False
    assert host.ssl_forced is False
    assert host.block_exploits is True


def test_stream_minimal():
    stream = Stream(
        incoming_port=8080,
        forwarding_host="192.168.1.1",
        forwarding_port=80,
    )
    assert stream.tcp_forwarding is True
    assert stream.udp_forwarding is False
    assert stream.enabled is True


def test_dead_host_minimal():
    host = DeadHost(domain_names=["dead.ex.com"])
    assert host.ssl_forced is False
    assert host.http2_support is False
    assert host.enabled is True


def test_user_minimal():
    user = User(name="Test", email="test@ex.com")
    assert user.nickname == ""
    assert user.is_disabled is False
    assert user.roles == []


def test_setting_defaults():
    setting = Setting()
    assert setting.value == ""
    assert setting.meta == {}


def test_audit_log_entry_defaults():
    entry = AuditLogEntry()
    assert entry.meta == {}
