"""Data models for NPM entities."""

from typing import List, Optional
from pydantic import BaseModel, Field


class ProxyHostLocation(BaseModel):
    path: str = "/"
    forward_scheme: str = "http"
    forward_host: str
    forward_port: int


class ProxyHost(BaseModel):
    id: Optional[int] = None
    created_on: Optional[str] = None
    modified_on: Optional[str] = None
    owner_user_id: Optional[int] = None
    domain_names: List[str]
    forward_scheme: str = "http"
    forward_host: str
    forward_port: int
    access_list_id: Optional[int] = None
    certificate_id: Optional[int] = None
    ssl_forced: bool = False
    caching_enabled: bool = False
    block_exploits: bool = True
    advanced_config: str = ""
    meta: dict = Field(default_factory=dict)
    allow_websocket_upgrade: bool = False
    http2_support: bool = False
    hsts_enabled: bool = False
    hsts_subdomains: bool = False
    enabled: bool = True
    locations: List[ProxyHostLocation] = Field(default_factory=list)


class Certificate(BaseModel):
    id: Optional[int] = None
    created_on: Optional[str] = None
    modified_on: Optional[str] = None
    provider: str = "letsencrypt"
    nice_name: str
    domain_names: List[str]
    expires_on: Optional[str] = None
    meta: dict = Field(default_factory=dict)


class AccessList(BaseModel):
    id: Optional[int] = None
    created_on: Optional[str] = None
    modified_on: Optional[str] = None
    name: str
    satisfy_any: bool = False
    pass_auth: bool = True
    meta: dict = Field(default_factory=dict)
    items: List[dict] = Field(default_factory=list)


class RedirectionHost(BaseModel):
    id: Optional[int] = None
    created_on: Optional[str] = None
    modified_on: Optional[str] = None
    owner_user_id: Optional[int] = None
    domain_names: List[str]
    forward_scheme: str = "auto"
    forward_http_code: int = 302
    forward_domain_name: str
    preserve_path: bool = False
    certificate_id: Optional[int] = None
    ssl_forced: bool = False
    hsts_enabled: bool = False
    hsts_subdomains: bool = False
    http2_support: bool = False
    block_exploits: bool = True
    advanced_config: str = ""
    meta: dict = Field(default_factory=dict)
    enabled: bool = True


class Stream(BaseModel):
    id: Optional[int] = None
    created_on: Optional[str] = None
    modified_on: Optional[str] = None
    owner_user_id: Optional[int] = None
    incoming_port: int
    forwarding_host: str
    forwarding_port: int
    tcp_forwarding: bool = True
    udp_forwarding: bool = False
    certificate_id: Optional[int] = None
    meta: dict = Field(default_factory=dict)
    enabled: bool = True


class DeadHost(BaseModel):
    id: Optional[int] = None
    created_on: Optional[str] = None
    modified_on: Optional[str] = None
    owner_user_id: Optional[int] = None
    domain_names: List[str]
    certificate_id: Optional[int] = None
    ssl_forced: bool = False
    hsts_enabled: bool = False
    hsts_subdomains: bool = False
    http2_support: bool = False
    advanced_config: str = ""
    meta: dict = Field(default_factory=dict)
    enabled: bool = True


class User(BaseModel):
    id: Optional[int] = None
    created_on: Optional[str] = None
    modified_on: Optional[str] = None
    name: str
    nickname: str = ""
    email: str
    avatar: str = ""
    roles: List[str] = Field(default_factory=list)
    is_disabled: bool = False


class Setting(BaseModel):
    id: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    value: str = ""
    meta: dict = Field(default_factory=dict)


class AuditLogEntry(BaseModel):
    id: Optional[int] = None
    created_on: Optional[str] = None
    modified_on: Optional[str] = None
    user_id: Optional[int] = None
    object_type: Optional[str] = None
    object_id: Optional[int] = None
    action: Optional[str] = None
    meta: dict = Field(default_factory=dict)


class NPMToken(BaseModel):
    token: str
    expires: str


class NPMConfig(BaseModel):
    url: str
    email: str
    password: str
