from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import pyotp
from cryptography.fernet import Fernet

from radius_totp.auth import AuthService
from radius_totp.crypto import SecretCipher
from radius_totp.storage import User2FA


@dataclass
class FakePasswordAuthenticator:
    passwords: dict[str, str]

    def authenticate(self, username: str, password: str) -> bool:
        return self.passwords.get(username.lower()) == password


class FakeStore:
    def __init__(self) -> None:
        self.users: dict[str, User2FA] = {}
        self.logs: list[tuple[str | None, str, str, str, str | None]] = []

    def get_user(self, username: str) -> User2FA | None:
        return self.users.get(username.lower())

    def upsert_user_secret(self, username: str, secret_encrypted: bytes, enabled: bool) -> None:
        self.users[username.lower()] = User2FA(
            username=username,
            secret_encrypted=secret_encrypted,
            is_enabled=enabled,
            last_used_timestep=None,
            created_at=datetime.now(timezone.utc),
        )

    def set_enabled(self, username: str, enabled: bool) -> None:
        user = self.users[username.lower()]
        self.users[username.lower()] = User2FA(
            username=user.username,
            secret_encrypted=user.secret_encrypted,
            is_enabled=enabled,
            last_used_timestep=user.last_used_timestep,
            created_at=user.created_at,
        )

    def reset_user(self, username: str) -> None:
        user = self.users[username.lower()]
        self.users[username.lower()] = User2FA(user.username, None, False, None, user.created_at)

    def update_last_used_timestep(self, username: str, timestep: int) -> None:
        user = self.users[username.lower()]
        self.users[username.lower()] = User2FA(
            username=user.username,
            secret_encrypted=user.secret_encrypted,
            is_enabled=user.is_enabled,
            last_used_timestep=timestep,
            created_at=user.created_at,
        )

    def log_auth(self, username: str | None, source: str, result: str, reason: str, radius_client: str | None = None) -> None:
        self.logs.append((username, source, result, reason, radius_client))


def make_service() -> tuple[AuthService, FakeStore, SecretCipher]:
    store = FakeStore()
    cipher = SecretCipher(Fernet.generate_key().decode("utf-8"))
    service = AuthService(
        store=store,
        password_authenticator=FakePasswordAuthenticator({"ivan": "correct-password", "numeric": "pass123456"}),
        cipher=cipher,
        otp_valid_window=1,
    )
    return service, store, cipher


def test_not_enrolled_user_is_allowed_after_ad_success() -> None:
    service, store, _ = make_service()

    result = service.authenticate_initial("ivan", "correct-password", "vpn1")

    assert result.ok is True
    assert result.reason == "2fa_not_enabled"
    assert store.logs[-1] == ("ivan", "radius", "accept", "2fa_not_enabled", "vpn1")


def test_enabled_user_gets_access_challenge_after_ad_success() -> None:
    service, store, cipher = make_service()
    store.upsert_user_secret("ivan", cipher.encrypt(pyotp.random_base32()), enabled=True)

    result = service.authenticate_initial("ivan", "correct-password", "vpn1")

    assert result.ok is False
    assert result.requires_challenge is True
    assert result.reason == "otp_required"


def test_password_plus_otp_accepts_enabled_user() -> None:
    service, store, cipher = make_service()
    secret = pyotp.random_base32()
    store.upsert_user_secret("ivan", cipher.encrypt(secret), enabled=True)
    code = pyotp.TOTP(secret).now()

    result = service.authenticate_initial("ivan", f"correct-password{code}", "vpn1")

    assert result.ok is True
    assert result.reason == "ok"
    assert store.get_user("ivan").last_used_timestep is not None


def test_reused_otp_is_rejected() -> None:
    service, store, cipher = make_service()
    secret = pyotp.random_base32()
    store.upsert_user_secret("ivan", cipher.encrypt(secret), enabled=True)
    code = pyotp.TOTP(secret).now()

    assert service.authenticate_otp("ivan", code, "vpn1").ok is True
    second = service.authenticate_otp("ivan", code, "vpn1")

    assert second.ok is False
    assert second.reason == "reused_totp"


def test_numeric_password_can_still_use_challenge_flow() -> None:
    service, store, cipher = make_service()
    store.upsert_user_secret("numeric", cipher.encrypt(pyotp.random_base32()), enabled=True)

    result = service.authenticate_initial("numeric", "pass123456", "vpn1")

    assert result.ok is False
    assert result.requires_challenge is True
    assert result.reason == "otp_required"
