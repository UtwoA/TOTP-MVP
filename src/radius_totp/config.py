from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _as_int(value: str | None, default: int) -> int:
    if value is None or value == "":
        return default
    return int(value)


@dataclass(frozen=True)
class RadiusClient:
    host: str
    secret: str
    name: str


@dataclass(frozen=True)
class Settings:
    database_dsn: str
    fernet_key: str
    auth_backend: str
    local_users: tuple[tuple[str, str], ...]
    ad_server: str
    ad_port: int
    ad_use_ssl: bool
    ad_start_tls: bool
    ad_tls_validate: bool
    ad_base_dn: str
    ad_user_upn_suffix: str
    ad_bind_dn: str | None
    ad_bind_password: str | None
    radius_listen_host: str
    radius_auth_port: int
    radius_dictionary: str
    radius_clients: tuple[RadiusClient, ...]
    otp_issuer: str
    otp_valid_window: int
    enable_password_otp: bool
    enable_access_challenge: bool


def parse_radius_clients(value: str) -> tuple[RadiusClient, ...]:
    clients: list[RadiusClient] = []
    for raw_item in value.split(","):
        item = raw_item.strip()
        if not item:
            continue
        parts = item.split(":", 2)
        if len(parts) < 2:
            raise ValueError("RADIUS_CLIENTS entries must be host:secret[:name]")
        host, secret = parts[0].strip(), parts[1].strip()
        name = parts[2].strip() if len(parts) == 3 and parts[2].strip() else host
        clients.append(RadiusClient(host=host, secret=secret, name=name))
    if not clients:
        raise ValueError("At least one RADIUS client must be configured")
    return tuple(clients)


def parse_local_users(value: str) -> tuple[tuple[str, str], ...]:
    users: list[tuple[str, str]] = []
    for raw_item in value.split(","):
        item = raw_item.strip()
        if not item:
            continue
        username, separator, password = item.partition(":")
        if not separator or not username or not password:
            raise ValueError("LOCAL_USERS entries must be username:password")
        users.append((username.strip().lower(), password))
    return tuple(users)


def load_settings(env_path: str | Path | None = None) -> Settings:
    load_dotenv(env_path)

    database_dsn = os.getenv("DATABASE_DSN", "")
    fernet_key = os.getenv("FERNET_KEY", "")
    auth_backend = os.getenv("AUTH_BACKEND", "ad").lower()
    local_users = os.getenv("LOCAL_USERS", "")
    ad_server = os.getenv("AD_SERVER", "")
    ad_base_dn = os.getenv("AD_BASE_DN", "")
    radius_clients = os.getenv("RADIUS_CLIENTS", "")

    required = {
        "DATABASE_DSN": database_dsn,
        "FERNET_KEY": fernet_key,
        "RADIUS_CLIENTS": radius_clients,
    }
    if auth_backend == "ad":
        required["AD_SERVER"] = ad_server
        required["AD_BASE_DN"] = ad_base_dn
    elif auth_backend == "local":
        required["LOCAL_USERS"] = local_users
    else:
        raise ValueError("AUTH_BACKEND must be either 'ad' or 'local'")

    missing = [name for name, value in required.items() if not value]
    if missing:
        raise ValueError(f"Missing required settings: {', '.join(missing)}")

    return Settings(
        database_dsn=database_dsn,
        fernet_key=fernet_key,
        auth_backend=auth_backend,
        local_users=parse_local_users(local_users),
        ad_server=ad_server,
        ad_port=_as_int(os.getenv("AD_PORT"), 636),
        ad_use_ssl=_as_bool(os.getenv("AD_USE_SSL"), True),
        ad_start_tls=_as_bool(os.getenv("AD_START_TLS"), False),
        ad_tls_validate=_as_bool(os.getenv("AD_TLS_VALIDATE"), True),
        ad_base_dn=ad_base_dn,
        ad_user_upn_suffix=os.getenv("AD_USER_UPN_SUFFIX", ""),
        ad_bind_dn=os.getenv("AD_BIND_DN") or None,
        ad_bind_password=os.getenv("AD_BIND_PASSWORD") or None,
        radius_listen_host=os.getenv("RADIUS_LISTEN_HOST", "0.0.0.0"),
        radius_auth_port=_as_int(os.getenv("RADIUS_AUTH_PORT"), 1812),
        radius_dictionary=os.getenv("RADIUS_DICTIONARY", "radius/dictionary"),
        radius_clients=parse_radius_clients(radius_clients),
        otp_issuer=os.getenv("OTP_ISSUER", "Corporate VPN"),
        otp_valid_window=_as_int(os.getenv("OTP_VALID_WINDOW"), 1),
        enable_password_otp=_as_bool(os.getenv("ENABLE_PASSWORD_OTP"), True),
        enable_access_challenge=_as_bool(os.getenv("ENABLE_ACCESS_CHALLENGE"), True),
    )
