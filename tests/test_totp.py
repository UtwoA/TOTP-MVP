from __future__ import annotations

import pyotp

from radius_totp.totp import build_otpauth_uri, split_password_otp, verify_totp


def test_split_password_otp_accepts_last_six_digits() -> None:
    assert split_password_otp("SecretPassword123456") == ("SecretPassword", "123456")


def test_split_password_otp_rejects_non_digit_suffix() -> None:
    assert split_password_otp("SecretPasswordabcdef") is None


def test_verify_totp_accepts_current_code_and_returns_timestep() -> None:
    secret = pyotp.random_base32()
    timestamp = 1_700_000_000
    code = pyotp.TOTP(secret).at(timestamp)

    result = verify_totp(secret, code, last_used_timestep=None, valid_window=1, for_time=timestamp)

    assert result.ok is True
    assert result.timestep == timestamp // 30


def test_verify_totp_rejects_reused_or_older_timestep() -> None:
    secret = pyotp.random_base32()
    timestamp = 1_700_000_000
    code = pyotp.TOTP(secret).at(timestamp)

    result = verify_totp(secret, code, last_used_timestep=timestamp // 30, valid_window=1, for_time=timestamp)

    assert result.ok is False
    assert result.reason == "reused_totp"


def test_build_otpauth_uri_is_totp_compatible() -> None:
    uri = build_otpauth_uri("JBSWY3DPEHPK3PXP", "ivan.petrov", "Corporate VPN")

    assert uri.startswith("otpauth://totp/Corporate%20VPN:ivan.petrov?")
    assert "issuer=Corporate%20VPN" in uri
