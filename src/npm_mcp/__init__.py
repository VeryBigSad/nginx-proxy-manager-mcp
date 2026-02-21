"""Nginx Proxy Manager MCP Server."""

from .client import (
    NPMClient,
    NPMClientError,
    NPMConfigError,
    NPMAuthenticationError,
    NPMNetworkError,
    create_client_from_env,
)
from .models import ProxyHost, Certificate, AccessList, NPMConfig

__version__ = "0.1.0"

__all__ = [
    "NPMClient",
    "NPMClientError",
    "NPMConfigError",
    "NPMAuthenticationError",
    "NPMNetworkError",
    "create_client_from_env",
    "ProxyHost",
    "Certificate",
    "AccessList",
    "NPMConfig",
]
