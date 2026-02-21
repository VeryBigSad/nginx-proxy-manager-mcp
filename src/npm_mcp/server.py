"""MCP server for Nginx Proxy Manager."""

import asyncio
import json
from typing import Any
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
from .client import create_client_from_env, NPMClient
from .models import (
    ProxyHost, Certificate, AccessList, RedirectionHost,
    Stream, DeadHost, User, Setting, AuditLogEntry,
)


app = Server("nginx-proxy-manager")
npm_client: NPMClient | None = None


def _id_schema(name: str, desc: str) -> dict:
    return {
        "type": "object",
        "properties": {name: {"type": "integer", "description": desc}},
        "required": [name],
    }


def _empty_schema() -> dict:
    return {"type": "object", "properties": {}}


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        # --- Proxy Hosts ---
        Tool(name="list_proxy_hosts", description="List all proxy hosts configured in NPM", inputSchema=_empty_schema()),
        Tool(name="get_proxy_host", description="Get details of a specific proxy host by ID", inputSchema=_id_schema("host_id", "The ID of the proxy host")),
        Tool(
            name="create_proxy_host",
            description="Create a new proxy host",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain_names": {"type": "array", "items": {"type": "string"}, "description": "List of domain names"},
                    "forward_scheme": {"type": "string", "enum": ["http", "https"], "default": "http"},
                    "forward_host": {"type": "string", "description": "IP or hostname to forward to"},
                    "forward_port": {"type": "integer", "description": "Port to forward to"},
                    "certificate_id": {"type": "integer", "description": "SSL certificate ID"},
                    "ssl_forced": {"type": "boolean", "default": False},
                    "block_exploits": {"type": "boolean", "default": True},
                    "advanced_config": {"type": "string", "default": ""},
                },
                "required": ["domain_names", "forward_host", "forward_port"],
            },
        ),
        Tool(
            name="update_proxy_host",
            description="Update an existing proxy host",
            inputSchema={
                "type": "object",
                "properties": {
                    "host_id": {"type": "integer", "description": "The ID of the proxy host to update"},
                    "domain_names": {"type": "array", "items": {"type": "string"}},
                    "forward_scheme": {"type": "string", "enum": ["http", "https"]},
                    "forward_host": {"type": "string"},
                    "forward_port": {"type": "integer"},
                    "certificate_id": {"type": "integer"},
                    "ssl_forced": {"type": "boolean"},
                    "block_exploits": {"type": "boolean"},
                    "advanced_config": {"type": "string"},
                },
                "required": ["host_id"],
            },
        ),
        Tool(name="delete_proxy_host", description="Delete a proxy host by ID", inputSchema=_id_schema("host_id", "The ID of the proxy host to delete")),
        Tool(name="enable_proxy_host", description="Enable a proxy host", inputSchema=_id_schema("host_id", "The ID of the proxy host to enable")),
        Tool(name="disable_proxy_host", description="Disable a proxy host", inputSchema=_id_schema("host_id", "The ID of the proxy host to disable")),

        # --- Redirection Hosts ---
        Tool(name="list_redirection_hosts", description="List all redirection hosts", inputSchema=_empty_schema()),
        Tool(name="get_redirection_host", description="Get a specific redirection host by ID", inputSchema=_id_schema("host_id", "The ID of the redirection host")),
        Tool(
            name="create_redirection_host",
            description="Create a new redirection host (HTTP redirect)",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain_names": {"type": "array", "items": {"type": "string"}, "description": "List of domain names"},
                    "forward_scheme": {"type": "string", "enum": ["auto", "http", "https"], "default": "auto"},
                    "forward_http_code": {"type": "integer", "description": "HTTP redirect code (301, 302, etc.)", "enum": [300, 301, 302, 303, 304, 305, 307, 308]},
                    "forward_domain_name": {"type": "string", "description": "Domain to redirect to"},
                    "preserve_path": {"type": "boolean", "default": False},
                    "certificate_id": {"type": "integer"},
                    "ssl_forced": {"type": "boolean", "default": False},
                    "block_exploits": {"type": "boolean", "default": True},
                    "advanced_config": {"type": "string", "default": ""},
                },
                "required": ["domain_names", "forward_http_code", "forward_domain_name"],
            },
        ),
        Tool(
            name="update_redirection_host",
            description="Update an existing redirection host",
            inputSchema={
                "type": "object",
                "properties": {
                    "host_id": {"type": "integer", "description": "The ID of the redirection host to update"},
                    "domain_names": {"type": "array", "items": {"type": "string"}},
                    "forward_scheme": {"type": "string", "enum": ["auto", "http", "https"]},
                    "forward_http_code": {"type": "integer"},
                    "forward_domain_name": {"type": "string"},
                    "preserve_path": {"type": "boolean"},
                    "certificate_id": {"type": "integer"},
                    "ssl_forced": {"type": "boolean"},
                    "block_exploits": {"type": "boolean"},
                    "advanced_config": {"type": "string"},
                },
                "required": ["host_id"],
            },
        ),
        Tool(name="delete_redirection_host", description="Delete a redirection host by ID", inputSchema=_id_schema("host_id", "The ID of the redirection host to delete")),
        Tool(name="enable_redirection_host", description="Enable a redirection host", inputSchema=_id_schema("host_id", "The ID of the redirection host to enable")),
        Tool(name="disable_redirection_host", description="Disable a redirection host", inputSchema=_id_schema("host_id", "The ID of the redirection host to disable")),

        # --- Streams ---
        Tool(name="list_streams", description="List all TCP/UDP stream proxies", inputSchema=_empty_schema()),
        Tool(name="get_stream", description="Get a specific stream by ID", inputSchema=_id_schema("stream_id", "The ID of the stream")),
        Tool(
            name="create_stream",
            description="Create a new TCP/UDP stream proxy",
            inputSchema={
                "type": "object",
                "properties": {
                    "incoming_port": {"type": "integer", "description": "Port to listen on (1-65535)"},
                    "forwarding_host": {"type": "string", "description": "Host to forward to"},
                    "forwarding_port": {"type": "integer", "description": "Port to forward to (1-65535)"},
                    "tcp_forwarding": {"type": "boolean", "default": True},
                    "udp_forwarding": {"type": "boolean", "default": False},
                    "certificate_id": {"type": "integer"},
                },
                "required": ["incoming_port", "forwarding_host", "forwarding_port"],
            },
        ),
        Tool(
            name="update_stream",
            description="Update an existing stream",
            inputSchema={
                "type": "object",
                "properties": {
                    "stream_id": {"type": "integer", "description": "The ID of the stream to update"},
                    "incoming_port": {"type": "integer"},
                    "forwarding_host": {"type": "string"},
                    "forwarding_port": {"type": "integer"},
                    "tcp_forwarding": {"type": "boolean"},
                    "udp_forwarding": {"type": "boolean"},
                    "certificate_id": {"type": "integer"},
                },
                "required": ["stream_id"],
            },
        ),
        Tool(name="delete_stream", description="Delete a stream by ID", inputSchema=_id_schema("stream_id", "The ID of the stream to delete")),
        Tool(name="enable_stream", description="Enable a stream", inputSchema=_id_schema("stream_id", "The ID of the stream to enable")),
        Tool(name="disable_stream", description="Disable a stream", inputSchema=_id_schema("stream_id", "The ID of the stream to disable")),

        # --- Dead Hosts (404) ---
        Tool(name="list_dead_hosts", description="List all 404 dead hosts", inputSchema=_empty_schema()),
        Tool(name="get_dead_host", description="Get a specific dead host by ID", inputSchema=_id_schema("host_id", "The ID of the dead host")),
        Tool(
            name="create_dead_host",
            description="Create a new 404 dead host",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain_names": {"type": "array", "items": {"type": "string"}, "description": "List of domain names"},
                    "certificate_id": {"type": "integer"},
                    "ssl_forced": {"type": "boolean", "default": False},
                    "hsts_enabled": {"type": "boolean", "default": False},
                    "hsts_subdomains": {"type": "boolean", "default": False},
                    "http2_support": {"type": "boolean", "default": False},
                    "advanced_config": {"type": "string", "default": ""},
                },
                "required": ["domain_names"],
            },
        ),
        Tool(
            name="update_dead_host",
            description="Update an existing dead host",
            inputSchema={
                "type": "object",
                "properties": {
                    "host_id": {"type": "integer", "description": "The ID of the dead host to update"},
                    "domain_names": {"type": "array", "items": {"type": "string"}},
                    "certificate_id": {"type": "integer"},
                    "ssl_forced": {"type": "boolean"},
                    "hsts_enabled": {"type": "boolean"},
                    "hsts_subdomains": {"type": "boolean"},
                    "http2_support": {"type": "boolean"},
                    "advanced_config": {"type": "string"},
                },
                "required": ["host_id"],
            },
        ),
        Tool(name="delete_dead_host", description="Delete a dead host by ID", inputSchema=_id_schema("host_id", "The ID of the dead host to delete")),
        Tool(name="enable_dead_host", description="Enable a dead host", inputSchema=_id_schema("host_id", "The ID of the dead host to enable")),
        Tool(name="disable_dead_host", description="Disable a dead host", inputSchema=_id_schema("host_id", "The ID of the dead host to disable")),

        # --- Certificates ---
        Tool(name="list_certificates", description="List all SSL certificates in NPM", inputSchema=_empty_schema()),
        Tool(name="get_certificate", description="Get a specific SSL certificate by ID", inputSchema=_id_schema("certificate_id", "The ID of the certificate")),
        Tool(
            name="request_certificate",
            description="Request a new Let's Encrypt SSL certificate",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain_names": {"type": "array", "items": {"type": "string"}, "description": "List of domains for the certificate"},
                    "nice_name": {"type": "string", "description": "Friendly name for the certificate"},
                },
                "required": ["domain_names", "nice_name"],
            },
        ),
        Tool(name="delete_certificate", description="Delete an SSL certificate by ID", inputSchema=_id_schema("certificate_id", "The ID of the certificate to delete")),
        Tool(name="renew_certificate", description="Renew a Let's Encrypt certificate", inputSchema=_id_schema("certificate_id", "The ID of the certificate to renew")),
        Tool(name="list_dns_providers", description="List supported DNS providers for DNS challenge certificates", inputSchema=_empty_schema()),
        Tool(
            name="test_http_challenge",
            description="Test if domains are reachable for HTTP-01 ACME challenge",
            inputSchema={
                "type": "object",
                "properties": {
                    "domains": {"type": "array", "items": {"type": "string"}, "description": "List of domains to test"},
                },
                "required": ["domains"],
            },
        ),

        # --- Access Lists ---
        Tool(name="list_access_lists", description="List all access lists (basic auth, IP restrictions)", inputSchema=_empty_schema()),
        Tool(name="get_access_list", description="Get a specific access list by ID", inputSchema=_id_schema("access_list_id", "The ID of the access list")),
        Tool(
            name="create_access_list",
            description="Create a new access list",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Name of the access list"},
                    "satisfy_any": {"type": "boolean", "default": False},
                    "pass_auth": {"type": "boolean", "default": True},
                },
                "required": ["name"],
            },
        ),
        Tool(
            name="update_access_list",
            description="Update an existing access list",
            inputSchema={
                "type": "object",
                "properties": {
                    "access_list_id": {"type": "integer"},
                    "name": {"type": "string"},
                    "satisfy_any": {"type": "boolean"},
                    "pass_auth": {"type": "boolean"},
                },
                "required": ["access_list_id"],
            },
        ),
        Tool(name="delete_access_list", description="Delete an access list by ID", inputSchema=_id_schema("access_list_id", "The ID of the access list to delete")),

        # --- Users ---
        Tool(name="list_users", description="List all NPM users", inputSchema=_empty_schema()),
        Tool(name="get_user", description="Get a specific user by ID", inputSchema=_id_schema("user_id", "The ID of the user")),
        Tool(
            name="create_user",
            description="Create a new NPM user",
            inputSchema={
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Full name"},
                    "nickname": {"type": "string", "default": ""},
                    "email": {"type": "string", "description": "Email address"},
                    "roles": {"type": "array", "items": {"type": "string"}, "description": "Roles (e.g. admin)"},
                    "is_disabled": {"type": "boolean", "default": False},
                },
                "required": ["name", "email"],
            },
        ),
        Tool(
            name="update_user",
            description="Update an existing NPM user",
            inputSchema={
                "type": "object",
                "properties": {
                    "user_id": {"type": "integer", "description": "The ID of the user to update"},
                    "name": {"type": "string"},
                    "nickname": {"type": "string"},
                    "email": {"type": "string"},
                    "roles": {"type": "array", "items": {"type": "string"}},
                    "is_disabled": {"type": "boolean"},
                },
                "required": ["user_id"],
            },
        ),
        Tool(name="delete_user", description="Delete a user by ID", inputSchema=_id_schema("user_id", "The ID of the user to delete")),

        # --- Settings ---
        Tool(name="list_settings", description="List all NPM settings", inputSchema=_empty_schema()),
        Tool(
            name="get_setting",
            description="Get a specific setting by ID",
            inputSchema={
                "type": "object",
                "properties": {"setting_id": {"type": "string", "description": "The setting ID (e.g. 'default-site')"}},
                "required": ["setting_id"],
            },
        ),
        Tool(
            name="update_setting",
            description="Update a setting",
            inputSchema={
                "type": "object",
                "properties": {
                    "setting_id": {"type": "string", "description": "The setting ID"},
                    "value": {"type": "string", "description": "Setting value"},
                    "meta": {"type": "object", "description": "Setting metadata"},
                },
                "required": ["setting_id"],
            },
        ),

        # --- Audit Log ---
        Tool(name="list_audit_log", description="List recent audit log entries", inputSchema=_empty_schema()),

        # --- Reports ---
        Tool(name="get_host_report", description="Get host count report (proxy, redirection, stream, dead)", inputSchema=_empty_schema()),
    ]


def _json_response(data: Any) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(data, indent=2))]


def _model_response(obj: Any) -> list[TextContent]:
    return _json_response(obj.model_dump())


def _list_response(items: list) -> list[TextContent]:
    return _json_response([item.model_dump() for item in items])


def _msg_response(msg: str) -> list[TextContent]:
    return [TextContent(type="text", text=msg)]


@app.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    global npm_client
    if npm_client is None:
        npm_client = create_client_from_env()

    try:
        # --- Proxy Hosts ---
        if name == "list_proxy_hosts":
            return _list_response(await npm_client.list_proxy_hosts())
        elif name == "get_proxy_host":
            return _model_response(await npm_client.get_proxy_host(arguments["host_id"]))
        elif name == "create_proxy_host":
            return _model_response(await npm_client.create_proxy_host(ProxyHost(**arguments)))
        elif name == "update_proxy_host":
            host_id = arguments.pop("host_id")
            current = await npm_client.get_proxy_host(host_id)
            updated_data = current.model_dump()
            updated_data.update(arguments)
            return _model_response(await npm_client.update_proxy_host(host_id, ProxyHost(**updated_data)))
        elif name == "delete_proxy_host":
            await npm_client.delete_proxy_host(arguments["host_id"])
            return _msg_response("Proxy host deleted successfully")
        elif name == "enable_proxy_host":
            await npm_client.enable_proxy_host(arguments["host_id"])
            return _msg_response("Proxy host enabled successfully")
        elif name == "disable_proxy_host":
            await npm_client.disable_proxy_host(arguments["host_id"])
            return _msg_response("Proxy host disabled successfully")

        # --- Redirection Hosts ---
        elif name == "list_redirection_hosts":
            return _list_response(await npm_client.list_redirection_hosts())
        elif name == "get_redirection_host":
            return _model_response(await npm_client.get_redirection_host(arguments["host_id"]))
        elif name == "create_redirection_host":
            return _model_response(await npm_client.create_redirection_host(RedirectionHost(**arguments)))
        elif name == "update_redirection_host":
            host_id = arguments.pop("host_id")
            current = await npm_client.get_redirection_host(host_id)
            updated_data = current.model_dump()
            updated_data.update(arguments)
            return _model_response(await npm_client.update_redirection_host(host_id, RedirectionHost(**updated_data)))
        elif name == "delete_redirection_host":
            await npm_client.delete_redirection_host(arguments["host_id"])
            return _msg_response("Redirection host deleted successfully")
        elif name == "enable_redirection_host":
            await npm_client.enable_redirection_host(arguments["host_id"])
            return _msg_response("Redirection host enabled successfully")
        elif name == "disable_redirection_host":
            await npm_client.disable_redirection_host(arguments["host_id"])
            return _msg_response("Redirection host disabled successfully")

        # --- Streams ---
        elif name == "list_streams":
            return _list_response(await npm_client.list_streams())
        elif name == "get_stream":
            return _model_response(await npm_client.get_stream(arguments["stream_id"]))
        elif name == "create_stream":
            return _model_response(await npm_client.create_stream(Stream(**arguments)))
        elif name == "update_stream":
            stream_id = arguments.pop("stream_id")
            current = await npm_client.get_stream(stream_id)
            updated_data = current.model_dump()
            updated_data.update(arguments)
            return _model_response(await npm_client.update_stream(stream_id, Stream(**updated_data)))
        elif name == "delete_stream":
            await npm_client.delete_stream(arguments["stream_id"])
            return _msg_response("Stream deleted successfully")
        elif name == "enable_stream":
            await npm_client.enable_stream(arguments["stream_id"])
            return _msg_response("Stream enabled successfully")
        elif name == "disable_stream":
            await npm_client.disable_stream(arguments["stream_id"])
            return _msg_response("Stream disabled successfully")

        # --- Dead Hosts ---
        elif name == "list_dead_hosts":
            return _list_response(await npm_client.list_dead_hosts())
        elif name == "get_dead_host":
            return _model_response(await npm_client.get_dead_host(arguments["host_id"]))
        elif name == "create_dead_host":
            return _model_response(await npm_client.create_dead_host(DeadHost(**arguments)))
        elif name == "update_dead_host":
            host_id = arguments.pop("host_id")
            current = await npm_client.get_dead_host(host_id)
            updated_data = current.model_dump()
            updated_data.update(arguments)
            return _model_response(await npm_client.update_dead_host(host_id, DeadHost(**updated_data)))
        elif name == "delete_dead_host":
            await npm_client.delete_dead_host(arguments["host_id"])
            return _msg_response("Dead host deleted successfully")
        elif name == "enable_dead_host":
            await npm_client.enable_dead_host(arguments["host_id"])
            return _msg_response("Dead host enabled successfully")
        elif name == "disable_dead_host":
            await npm_client.disable_dead_host(arguments["host_id"])
            return _msg_response("Dead host disabled successfully")

        # --- Certificates ---
        elif name == "list_certificates":
            return _list_response(await npm_client.list_certificates())
        elif name == "get_certificate":
            return _model_response(await npm_client.get_certificate(arguments["certificate_id"]))
        elif name == "request_certificate":
            return _model_response(await npm_client.request_certificate(Certificate(**arguments)))
        elif name == "delete_certificate":
            await npm_client.delete_certificate(arguments["certificate_id"])
            return _msg_response("Certificate deleted successfully")
        elif name == "renew_certificate":
            return _model_response(await npm_client.renew_certificate(arguments["certificate_id"]))
        elif name == "list_dns_providers":
            return _json_response(await npm_client.list_dns_providers())
        elif name == "test_http_challenge":
            return _json_response(await npm_client.test_http_challenge(arguments["domains"]))

        # --- Access Lists ---
        elif name == "list_access_lists":
            return _list_response(await npm_client.list_access_lists())
        elif name == "get_access_list":
            return _model_response(await npm_client.get_access_list(arguments["access_list_id"]))
        elif name == "create_access_list":
            return _model_response(await npm_client.create_access_list(AccessList(**arguments)))
        elif name == "update_access_list":
            access_list_id = arguments.pop("access_list_id")
            current = await npm_client.get_access_list(access_list_id)
            updated_data = current.model_dump()
            updated_data.update(arguments)
            return _model_response(await npm_client.update_access_list(access_list_id, AccessList(**updated_data)))
        elif name == "delete_access_list":
            await npm_client.delete_access_list(arguments["access_list_id"])
            return _msg_response("Access list deleted successfully")

        # --- Users ---
        elif name == "list_users":
            return _list_response(await npm_client.list_users())
        elif name == "get_user":
            return _model_response(await npm_client.get_user(arguments["user_id"]))
        elif name == "create_user":
            return _model_response(await npm_client.create_user(User(**arguments)))
        elif name == "update_user":
            user_id = arguments.pop("user_id")
            current = await npm_client.get_user(user_id)
            updated_data = current.model_dump()
            updated_data.update(arguments)
            return _model_response(await npm_client.update_user(user_id, User(**updated_data)))
        elif name == "delete_user":
            await npm_client.delete_user(arguments["user_id"])
            return _msg_response("User deleted successfully")

        # --- Settings ---
        elif name == "list_settings":
            return _list_response(await npm_client.list_settings())
        elif name == "get_setting":
            return _model_response(await npm_client.get_setting(arguments["setting_id"]))
        elif name == "update_setting":
            setting_id = arguments.pop("setting_id")
            current = await npm_client.get_setting(setting_id)
            updated_data = current.model_dump()
            updated_data.update(arguments)
            return _model_response(await npm_client.update_setting(setting_id, Setting(**updated_data)))

        # --- Audit Log ---
        elif name == "list_audit_log":
            return _list_response(await npm_client.list_audit_log())

        # --- Reports ---
        elif name == "get_host_report":
            return _json_response(await npm_client.get_host_report())

        else:
            raise ValueError(f"Unknown tool: {name}")

    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]


async def async_main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
