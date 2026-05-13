from __future__ import annotations

import re
import time
from dataclasses import dataclass

import pyotp


OTP_RE = re.compile(r"^\d{6}$")


@dataclass(frozen=True)
class TotpResult:
    ok: bool
    timestep: int | None = None
    reason: str = "ok"


def generate_secret() -> str:
    return pyotp.random_base32()


def build_otpauth_uri(secret: str, username: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def current_timestep(for_time: int | None = None, interval: int = 30) -> int:
    timestamp = int(time.time()) if for_time is None else int(for_time)
    return timestamp // interval


def split_password_otp(value: str) -> tuple[str, str] | None:
    if len(value) < 7:
        return None
    password, otp = value[:-6], value[-6:]
    if not OTP_RE.fullmatch(otp):
        return None
    return password, otp


def verify_totp(
    secret: str,
    otp: str,
    last_used_timestep: int | None,
    valid_window: int = 1,
    for_time: int | None = None,
) -> TotpResult:
    if not OTP_RE.fullmatch(otp):
        return TotpResult(ok=False, reason="invalid_format")

    totp = pyotp.TOTP(secret)
    timestamp = int(time.time()) if for_time is None else int(for_time)
    matched_timestep: int | None = None

    for offset in range(-valid_window, valid_window + 1):
        candidate_time = timestamp + (offset * totp.interval)
        if totp.verify(otp, for_time=candidate_time, valid_window=0):
            matched_timestep = current_timestep(candidate_time, totp.interval)
            break

    if matched_timestep is None:
        return TotpResult(ok=False, reason="invalid_totp")
    if last_used_timestep is not None and matched_timestep <= last_used_timestep:
        return TotpResult(ok=False, timestep=matched_timestep, reason="reused_totp")
    return TotpResult(ok=True, timestep=matched_timestep)
