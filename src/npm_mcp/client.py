"""NPM API client with authentication handling."""

import os
from typing import Optional, List
import httpx
from .models import (
    ProxyHost, Certificate, AccessList, RedirectionHost,
    Stream, DeadHost, User, Setting, AuditLogEntry, NPMConfig,
)


class NPMClientError(Exception):
    pass


class NPMConfigError(NPMClientError):
    pass


class NPMAuthenticationError(NPMClientError):
    pass


class NPMNetworkError(NPMClientError):
    pass


class NPMClient:
    def __init__(self, config: NPMConfig):
        self.config = config
        self.base_url = config.url.rstrip("/") if config.url else ""
        self._token: Optional[str] = None
        self._client = httpx.AsyncClient(timeout=30.0)

    def _validate_config(self):
        if not self.config.url:
            raise NPMConfigError("NPM_URL is required but not set")
        if not self.config.email:
            raise NPMConfigError("NPM_EMAIL is required but not set")
        if not self.config.password:
            raise NPMConfigError("NPM_PASSWORD is required but not set")

    async def _get_token(self) -> str:
        if self._token:
            return self._token

        self._validate_config()

        try:
            response = await self._client.post(
                f"{self.base_url}/api/tokens",
                json={
                    "identity": self.config.email,
                    "secret": self.config.password,
                },
            )
            response.raise_for_status()
            data = response.json()
            self._token = data["token"]
            return self._token
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise NPMAuthenticationError(
                    "Authentication failed: invalid NPM email or password"
                ) from e
            raise NPMNetworkError(f"HTTP error {e.response.status_code}: {e.response.text}") from e
        except httpx.ConnectError as e:
            raise NPMNetworkError(
                f"Cannot connect to NPM at {self.base_url}. Check NPM_URL is correct and NPM is running."
            ) from e
        except httpx.TimeoutException as e:
            raise NPMNetworkError(f"Request to NPM timed out after 30s") from e
        except Exception as e:
            raise NPMNetworkError(f"Unexpected error connecting to NPM: {e}") from e

    async def _request(
        self,
        method: str,
        path: str,
        retry_auth: bool = True,
        **kwargs,
    ) -> httpx.Response:
        try:
            token = await self._get_token()
            headers = kwargs.pop("headers", {})
            headers["Authorization"] = f"Bearer {token}"

            response = await self._client.request(
                method,
                f"{self.base_url}{path}",
                headers=headers,
                **kwargs,
            )

            if response.status_code == 401 and retry_auth:
                self._token = None
                return await self._request(method, path, retry_auth=False, **kwargs)

            response.raise_for_status()
            return response
        except httpx.HTTPStatusError as e:
            raise NPMNetworkError(
                f"HTTP {e.response.status_code} error on {method} {path}: {e.response.text}"
            ) from e
        except httpx.ConnectError as e:
            raise NPMNetworkError(
                f"Cannot connect to NPM at {self.base_url}. Check network connectivity."
            ) from e
        except httpx.TimeoutException as e:
            raise NPMNetworkError(f"Request to NPM timed out after 30s") from e

    async def list_proxy_hosts(self) -> List[ProxyHost]:
        response = await self._request("GET", "/api/nginx/proxy-hosts")
        return [ProxyHost(**host) for host in response.json()]

    async def get_proxy_host(self, host_id: int) -> ProxyHost:
        response = await self._request("GET", f"/api/nginx/proxy-hosts/{host_id}")
        return ProxyHost(**response.json())

    async def create_proxy_host(self, host: ProxyHost) -> ProxyHost:
        response = await self._request(
            "POST",
            "/api/nginx/proxy-hosts",
            json=host.model_dump(exclude_none=True, exclude={"id", "created_on", "modified_on"}),
        )
        return ProxyHost(**response.json())

    async def update_proxy_host(self, host_id: int, host: ProxyHost) -> ProxyHost:
        response = await self._request(
            "PUT",
            f"/api/nginx/proxy-hosts/{host_id}",
            json=host.model_dump(exclude_none=True, exclude={"id", "created_on", "modified_on", "owner_user_id"}),
        )
        return ProxyHost(**response.json())

    async def delete_proxy_host(self, host_id: int) -> None:
        await self._request("DELETE", f"/api/nginx/proxy-hosts/{host_id}")

    async def enable_proxy_host(self, host_id: int) -> None:
        await self._request("POST", f"/api/nginx/proxy-hosts/{host_id}/enable")

    async def disable_proxy_host(self, host_id: int) -> None:
        await self._request("POST", f"/api/nginx/proxy-hosts/{host_id}/disable")

    async def list_certificates(self) -> List[Certificate]:
        response = await self._request("GET", "/api/nginx/certificates")
        return [Certificate(**cert) for cert in response.json()]

    async def request_certificate(self, cert: Certificate) -> Certificate:
        response = await self._request(
            "POST",
            "/api/nginx/certificates",
            json=cert.model_dump(exclude_none=True, exclude={"id", "created_on", "modified_on"}),
        )
        return Certificate(**response.json())

    async def get_certificate(self, cert_id: int) -> Certificate:
        response = await self._request("GET", f"/api/nginx/certificates/{cert_id}")
        return Certificate(**response.json())

    async def delete_certificate(self, cert_id: int) -> None:
        await self._request("DELETE", f"/api/nginx/certificates/{cert_id}")

    async def renew_certificate(self, cert_id: int) -> Certificate:
        response = await self._request("POST", f"/api/nginx/certificates/{cert_id}/renew")
        return Certificate(**response.json())

    async def list_dns_providers(self) -> list[dict]:
        response = await self._request("GET", "/api/nginx/certificates/dns-providers")
        return response.json()

    async def test_http_challenge(self, domains: List[str]) -> dict:
        response = await self._request(
            "POST", "/api/nginx/certificates/test-http", json={"domains": domains}
        )
        return response.json()

    async def list_access_lists(self) -> List[AccessList]:
        response = await self._request("GET", "/api/nginx/access-lists")
        return [AccessList(**al) for al in response.json()]

    async def create_access_list(self, access_list: AccessList) -> AccessList:
        response = await self._request(
            "POST",
            "/api/nginx/access-lists",
            json=access_list.model_dump(exclude_none=True, exclude={"id", "created_on", "modified_on"}),
        )
        return AccessList(**response.json())

    async def update_access_list(self, access_list_id: int, access_list: AccessList) -> AccessList:
        response = await self._request(
            "PUT",
            f"/api/nginx/access-lists/{access_list_id}",
            json=access_list.model_dump(exclude_none=True, exclude={"id", "created_on", "modified_on"}),
        )
        return AccessList(**response.json())

    async def get_access_list(self, access_list_id: int) -> AccessList:
        response = await self._request("GET", f"/api/nginx/access-lists/{access_list_id}")
        return AccessList(**response.json())

    async def delete_access_list(self, access_list_id: int) -> None:
        await self._request("DELETE", f"/api/nginx/access-lists/{access_list_id}")

    async def list_redirection_hosts(self) -> List[RedirectionHost]:
        response = await self._request("GET", "/api/nginx/redirection-hosts")
        return [RedirectionHost(**h) for h in response.json()]

    async def get_redirection_host(self, host_id: int) -> RedirectionHost:
        response = await self._request("GET", f"/api/nginx/redirection-hosts/{host_id}")
        return RedirectionHost(**response.json())

    async def create_redirection_host(self, host: RedirectionHost) -> RedirectionHost:
        response = await self._request(
            "POST", "/api/nginx/redirection-hosts",
            json=host.model_dump(exclude_none=True, exclude={"id", "created_on", "modified_on"}),
        )
        return RedirectionHost(**response.json())

    async def update_redirection_host(self, host_id: int, host: RedirectionHost) -> RedirectionHost:
        response = await self._request(
            "PUT", f"/api/nginx/redirection-hosts/{host_id}",
            json=host.model_dump(exclude_none=True, exclude={"id", "created_on", "modified_on", "owner_user_id"}),
        )
        return RedirectionHost(**response.json())

    async def delete_redirection_host(self, host_id: int) -> None:
        await self._request("DELETE", f"/api/nginx/redirection-hosts/{host_id}")

    async def enable_redirection_host(self, host_id: int) -> None:
        await self._request("POST", f"/api/nginx/redirection-hosts/{host_id}/enable")

    async def disable_redirection_host(self, host_id: int) -> None:
        await self._request("POST", f"/api/nginx/redirection-hosts/{host_id}/disable")

    async def list_streams(self) -> List[Stream]:
        response = await self._request("GET", "/api/nginx/streams")
        return [Stream(**s) for s in response.json()]

    async def get_stream(self, stream_id: int) -> Stream:
        response = await self._request("GET", f"/api/nginx/streams/{stream_id}")
        return Stream(**response.json())

    async def create_stream(self, stream: Stream) -> Stream:
        response = await self._request(
            "POST", "/api/nginx/streams",
            json=stream.model_dump(exclude_none=True, exclude={"id", "created_on", "modified_on"}),
        )
        return Stream(**response.json())

    async def update_stream(self, stream_id: int, stream: Stream) -> Stream:
        response = await self._request(
            "PUT", f"/api/nginx/streams/{stream_id}",
            json=stream.model_dump(exclude_none=True, exclude={"id", "created_on", "modified_on", "owner_user_id"}),
        )
        return Stream(**response.json())

    async def delete_stream(self, stream_id: int) -> None:
        await self._request("DELETE", f"/api/nginx/streams/{stream_id}")

    async def enable_stream(self, stream_id: int) -> None:
        await self._request("POST", f"/api/nginx/streams/{stream_id}/enable")

    async def disable_stream(self, stream_id: int) -> None:
        await self._request("POST", f"/api/nginx/streams/{stream_id}/disable")

    async def list_dead_hosts(self) -> List[DeadHost]:
        response = await self._request("GET", "/api/nginx/dead-hosts")
        return [DeadHost(**h) for h in response.json()]

    async def get_dead_host(self, host_id: int) -> DeadHost:
        response = await self._request("GET", f"/api/nginx/dead-hosts/{host_id}")
        return DeadHost(**response.json())

    async def create_dead_host(self, host: DeadHost) -> DeadHost:
        response = await self._request(
            "POST", "/api/nginx/dead-hosts",
            json=host.model_dump(exclude_none=True, exclude={"id", "created_on", "modified_on"}),
        )
        return DeadHost(**response.json())

    async def update_dead_host(self, host_id: int, host: DeadHost) -> DeadHost:
        response = await self._request(
            "PUT", f"/api/nginx/dead-hosts/{host_id}",
            json=host.model_dump(exclude_none=True, exclude={"id", "created_on", "modified_on", "owner_user_id"}),
        )
        return DeadHost(**response.json())

    async def delete_dead_host(self, host_id: int) -> None:
        await self._request("DELETE", f"/api/nginx/dead-hosts/{host_id}")

    async def enable_dead_host(self, host_id: int) -> None:
        await self._request("POST", f"/api/nginx/dead-hosts/{host_id}/enable")

    async def disable_dead_host(self, host_id: int) -> None:
        await self._request("POST", f"/api/nginx/dead-hosts/{host_id}/disable")

    async def list_users(self) -> List[User]:
        response = await self._request("GET", "/api/users")
        return [User(**u) for u in response.json()]

    async def get_user(self, user_id: int) -> User:
        response = await self._request("GET", f"/api/users/{user_id}")
        return User(**response.json())

    async def create_user(self, user: User) -> User:
        response = await self._request(
            "POST", "/api/users",
            json=user.model_dump(exclude_none=True, exclude={"id", "created_on", "modified_on"}),
        )
        return User(**response.json())

    async def update_user(self, user_id: int, user: User) -> User:
        response = await self._request(
            "PUT", f"/api/users/{user_id}",
            json=user.model_dump(exclude_none=True, exclude={"id", "created_on", "modified_on"}),
        )
        return User(**response.json())

    async def delete_user(self, user_id: int) -> None:
        await self._request("DELETE", f"/api/users/{user_id}")

    async def list_settings(self) -> List[Setting]:
        response = await self._request("GET", "/api/settings")
        return [Setting(**s) for s in response.json()]

    async def get_setting(self, setting_id: str) -> Setting:
        response = await self._request("GET", f"/api/settings/{setting_id}")
        return Setting(**response.json())

    async def update_setting(self, setting_id: str, setting: Setting) -> Setting:
        response = await self._request(
            "PUT", f"/api/settings/{setting_id}",
            json=setting.model_dump(exclude_none=True, exclude={"id"}),
        )
        return Setting(**response.json())

    async def list_audit_log(self) -> List[AuditLogEntry]:
        response = await self._request("GET", "/api/audit-log")
        return [AuditLogEntry(**e) for e in response.json()]

    async def get_host_report(self) -> dict:
        response = await self._request("GET", "/api/reports/hosts")
        return response.json()

    async def close(self):
        await self._client.aclose()


def create_client_from_env() -> NPMClient:
    config = NPMConfig(
        url=os.getenv("NPM_URL", ""),
        email=os.getenv("NPM_EMAIL", ""),
        password=os.getenv("NPM_PASSWORD", ""),
    )
    return NPMClient(config)
