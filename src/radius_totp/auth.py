from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from radius_totp.crypto import SecretCipher
from radius_totp.storage import UserStore
from radius_totp.totp import split_password_otp, verify_totp


class PasswordAuthenticator(Protocol):
    def authenticate(self, username: str, password: str) -> bool:
        ...


@dataclass(frozen=True)
class AuthResult:
    ok: bool
    reason: str
    requires_challenge: bool = False


class AuthService:
    def __init__(
        self,
        store: UserStore,
        password_authenticator: PasswordAuthenticator,
        cipher: SecretCipher,
        otp_valid_window: int = 1,
        enable_password_otp: bool = True,
        enable_access_challenge: bool = True,
    ) -> None:
        self._store = store
        self._password_authenticator = password_authenticator
        self._cipher = cipher
        self._otp_valid_window = otp_valid_window
        self._enable_password_otp = enable_password_otp
        self._enable_access_challenge = enable_access_challenge

    def authenticate_initial(self, username: str, password_or_combined: str, radius_client: str | None = None) -> AuthResult:
        user = self._store.get_user(username)
        if user is not None and user.is_enabled and user.secret_encrypted and self._enable_password_otp:
            split = split_password_otp(password_or_combined)
            if split is not None:
                password, otp = split
                if self._password_authenticator.authenticate(username, password):
                    return self.authenticate_otp(username, otp, radius_client)

        if not self._password_authenticator.authenticate(username, password_or_combined):
            self._store.log_auth(username, "radius", "reject", "ad_auth_failed", radius_client)
            return AuthResult(ok=False, reason="ad_auth_failed")

        if user is None or not user.is_enabled or not user.secret_encrypted:
            self._store.log_auth(username, "radius", "accept", "2fa_not_enabled", radius_client)
            return AuthResult(ok=True, reason="2fa_not_enabled")

        if self._enable_access_challenge:
            self._store.log_auth(username, "radius", "challenge", "otp_required", radius_client)
            return AuthResult(ok=False, reason="otp_required", requires_challenge=True)

        self._store.log_auth(username, "radius", "reject", "otp_required_no_supported_flow", radius_client)
        return AuthResult(ok=False, reason="otp_required_no_supported_flow")

    def authenticate_password_and_otp(
        self,
        username: str,
        password: str,
        otp: str,
        radius_client: str | None = None,
    ) -> AuthResult:
        if not self._password_authenticator.authenticate(username, password):
            self._store.log_auth(username, "radius", "reject", "ad_auth_failed", radius_client)
            return AuthResult(ok=False, reason="ad_auth_failed")
        return self.authenticate_otp(username, otp, radius_client)

    def authenticate_otp(self, username: str, otp: str, radius_client: str | None = None) -> AuthResult:
        user = self._store.get_user(username)
        if user is None or not user.is_enabled or not user.secret_encrypted:
            self._store.log_auth(username, "radius", "accept", "2fa_not_enabled", radius_client)
            return AuthResult(ok=True, reason="2fa_not_enabled")

        secret = self._cipher.decrypt(user.secret_encrypted)
        result = verify_totp(secret, otp, user.last_used_timestep, self._otp_valid_window)
        if not result.ok or result.timestep is None:
            self._store.log_auth(username, "radius", "reject", result.reason, radius_client)
            return AuthResult(ok=False, reason=result.reason)

        self._store.update_last_used_timestep(username, result.timestep)
        self._store.log_auth(username, "radius", "accept", "ok", radius_client)
        return AuthResult(ok=True, reason="ok")

    def reject(self, username: str, reason: str, radius_client: str | None = None) -> AuthResult:
        self._store.log_auth(username, "radius", "reject", reason, radius_client)
        return AuthResult(ok=False, reason=reason)
