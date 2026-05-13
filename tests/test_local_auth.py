from __future__ import annotations

from radius_totp.local_auth import LocalPasswordAuthenticator


def test_local_password_authenticator_accepts_known_user() -> None:
    auth = LocalPasswordAuthenticator((("demo.user", "DemoPassword123"),))

    assert auth.authenticate("demo.user", "DemoPassword123") is True
    assert auth.authenticate("DEMO.USER", "DemoPassword123") is True


def test_local_password_authenticator_rejects_wrong_password() -> None:
    auth = LocalPasswordAuthenticator((("demo.user", "DemoPassword123"),))

    assert auth.authenticate("demo.user", "wrong") is False
    assert auth.authenticate("unknown", "DemoPassword123") is False
