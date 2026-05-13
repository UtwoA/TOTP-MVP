from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

import psycopg
from psycopg.rows import class_row


@dataclass(frozen=True)
class User2FA:
    username: str
    secret_encrypted: bytes | None
    is_enabled: bool
    last_used_timestep: int | None
    created_at: datetime


class UserStore(Protocol):
    def get_user(self, username: str) -> User2FA | None:
        ...

    def upsert_user_secret(self, username: str, secret_encrypted: bytes, enabled: bool) -> None:
        ...

    def set_enabled(self, username: str, enabled: bool) -> None:
        ...

    def reset_user(self, username: str) -> None:
        ...

    def update_last_used_timestep(self, username: str, timestep: int) -> None:
        ...

    def log_auth(self, username: str | None, source: str, result: str, reason: str, radius_client: str | None = None) -> None:
        ...


class PostgresUserStore:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn

    def get_user(self, username: str) -> User2FA | None:
        with psycopg.connect(self._dsn, row_factory=class_row(User2FA)) as conn:
            return conn.execute(
                """
                SELECT username, secret_encrypted, is_enabled, last_used_timestep, created_at
                FROM users
                WHERE lower(username) = lower(%s)
                """,
                (username,),
            ).fetchone()

    def upsert_user_secret(self, username: str, secret_encrypted: bytes, enabled: bool) -> None:
        with psycopg.connect(self._dsn) as conn:
            conn.execute(
                """
                INSERT INTO users (username, secret_encrypted, is_enabled, last_used_timestep)
                VALUES (%s, %s, %s, NULL)
                ON CONFLICT (username) DO UPDATE
                SET secret_encrypted = EXCLUDED.secret_encrypted,
                    is_enabled = EXCLUDED.is_enabled,
                    last_used_timestep = NULL
                """,
                (username, secret_encrypted, enabled),
            )

    def set_enabled(self, username: str, enabled: bool) -> None:
        with psycopg.connect(self._dsn) as conn:
            conn.execute("UPDATE users SET is_enabled = %s WHERE lower(username) = lower(%s)", (enabled, username))

    def reset_user(self, username: str) -> None:
        with psycopg.connect(self._dsn) as conn:
            conn.execute(
                """
                UPDATE users
                SET secret_encrypted = NULL,
                    is_enabled = FALSE,
                    last_used_timestep = NULL
                WHERE lower(username) = lower(%s)
                """,
                (username,),
            )

    def update_last_used_timestep(self, username: str, timestep: int) -> None:
        with psycopg.connect(self._dsn) as conn:
            conn.execute(
                """
                UPDATE users
                SET last_used_timestep = %s
                WHERE lower(username) = lower(%s)
                  AND (last_used_timestep IS NULL OR last_used_timestep < %s)
                """,
                (timestep, username, timestep),
            )

    def log_auth(self, username: str | None, source: str, result: str, reason: str, radius_client: str | None = None) -> None:
        with psycopg.connect(self._dsn) as conn:
            conn.execute(
                """
                INSERT INTO auth_logs (username, source, result, reason, radius_client)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (username, source, result, reason, radius_client),
            )
