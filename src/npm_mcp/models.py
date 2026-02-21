"""Data models for NPM entities."""

from typing import List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, SecretStr


class ProxyHostLocation(BaseModel):
    path: str = Field("/", max_length=1024)
    forward_scheme: Literal["http", "https"] = "http"
    forward_host: str = Field(..., max_length=255)
    forward_port: int = Field(..., ge=1, le=65535)


class ProxyHost(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: Optional[int] = None
    created_on: Optional[str] = None
    modified_on: Optional[str] = None
    owner_user_id: Optional[int] = None
    domain_names: List[str] = Field(..., max_length=100)
    forward_scheme: Literal["http", "https"] = "http"
    forward_host: str = Field(..., max_length=255)
    forward_port: int = Field(..., ge=1, le=65535)
    access_list_id: Optional[int] = None
    certificate_id: Optional[int] = None
    ssl_forced: bool = False
    caching_enabled: bool = False
    block_exploits: bool = True
    advanced_config: str = Field("", max_length=16384)
    meta: dict = Field(default_factory=dict)
    allow_websocket_upgrade: bool = False
    http2_support: bool = False
    hsts_enabled: bool = False
    hsts_subdomains: bool = False
    enabled: bool = True
    locations: List[ProxyHostLocation] = Field(default_factory=list)


class Certificate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: Optional[int] = None
    created_on: Optional[str] = None
    modified_on: Optional[str] = None
    provider: Literal["letsencrypt", "other"] = "letsencrypt"
    nice_name: str = Field(..., max_length=255)
    domain_names: List[str] = Field(..., max_length=100)
    expires_on: Optional[str] = None
    meta: dict = Field(default_factory=dict)


class AccessList(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: Optional[int] = None
    created_on: Optional[str] = None
    modified_on: Optional[str] = None
    name: str = Field(..., max_length=255)
    satisfy_any: bool = False
    pass_auth: bool = True
    meta: dict = Field(default_factory=dict)
    items: List[dict] = Field(default_factory=list)


class RedirectionHost(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: Optional[int] = None
    created_on: Optional[str] = None
    modified_on: Optional[str] = None
    owner_user_id: Optional[int] = None
    domain_names: List[str] = Field(..., max_length=100)
    forward_scheme: Literal["auto", "http", "https"] = "auto"
    forward_http_code: int = Field(302, ge=300, le=308)
    forward_domain_name: str = Field(..., max_length=255)
    preserve_path: bool = False
    certificate_id: Optional[int] = None
    ssl_forced: bool = False
    hsts_enabled: bool = False
    hsts_subdomains: bool = False
    http2_support: bool = False
    block_exploits: bool = True
    advanced_config: str = Field("", max_length=16384)
    meta: dict = Field(default_factory=dict)
    enabled: bool = True


class Stream(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: Optional[int] = None
    created_on: Optional[str] = None
    modified_on: Optional[str] = None
    owner_user_id: Optional[int] = None
    incoming_port: int = Field(..., ge=1, le=65535)
    forwarding_host: str = Field(..., max_length=255)
    forwarding_port: int = Field(..., ge=1, le=65535)
    tcp_forwarding: bool = True
    udp_forwarding: bool = False
    certificate_id: Optional[int] = None
    meta: dict = Field(default_factory=dict)
    enabled: bool = True


class DeadHost(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: Optional[int] = None
    created_on: Optional[str] = None
    modified_on: Optional[str] = None
    owner_user_id: Optional[int] = None
    domain_names: List[str] = Field(..., max_length=100)
    certificate_id: Optional[int] = None
    ssl_forced: bool = False
    hsts_enabled: bool = False
    hsts_subdomains: bool = False
    http2_support: bool = False
    advanced_config: str = Field("", max_length=16384)
    meta: dict = Field(default_factory=dict)
    enabled: bool = True


class User(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: Optional[int] = None
    created_on: Optional[str] = None
    modified_on: Optional[str] = None
    name: str = Field(..., max_length=255)
    nickname: str = Field("", max_length=255)
    email: str = Field(..., max_length=255)
    avatar: str = ""
    roles: List[str] = Field(default_factory=list)
    is_disabled: bool = False


class Setting(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: Optional[str] = None
    name: Optional[str] = None
    description: Optional[str] = None
    value: str = ""
    meta: dict = Field(default_factory=dict)


class AuditLogEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")

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
    password: SecretStr
