from __future__ import annotations

import ssl
from dataclasses import dataclass

from ldap3 import ALL, Connection, Server, Tls


@dataclass(frozen=True)
class ActiveDirectoryConfig:
    server: str
    port: int = 636
    use_ssl: bool = True
    start_tls: bool = False
    tls_validate: bool = True
    base_dn: str = ""
    user_upn_suffix: str = ""
    bind_dn: str | None = None
    bind_password: str | None = None


class ActiveDirectoryAuthenticator:
    def __init__(self, config: ActiveDirectoryConfig) -> None:
        self._config = config

    def authenticate(self, username: str, password: str) -> bool:
        user = self._format_login(username)
        conn: Connection | None = None
        server = Server(
            self._config.server,
            port=self._config.port,
            use_ssl=self._config.use_ssl,
            get_info=ALL,
            tls=Tls(validate=ssl.CERT_REQUIRED if self._config.tls_validate else ssl.CERT_NONE),
        )
        try:
            conn = Connection(server, user=user, password=password, auto_bind=False)
            if self._config.start_tls:
                conn.open()
                if not conn.start_tls():
                    return False
            return bool(conn.bind())
        except Exception:
            return False
        finally:
            try:
                if conn is not None:
                    conn.unbind()
            except Exception:
                pass

    def _format_login(self, username: str) -> str:
        if "\\" in username or "@" in username or not self._config.user_upn_suffix:
            return username
        return f"{username}@{self._config.user_upn_suffix}"
