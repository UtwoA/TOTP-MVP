from __future__ import annotations

import argparse
import getpass
import logging
import socket
from pathlib import Path

import qrcode
from pyrad import packet
from pyrad.dictionary import Dictionary

from radius_totp.ad import ActiveDirectoryAuthenticator, ActiveDirectoryConfig
from radius_totp.auth import AuthService
from radius_totp.config import Settings, load_settings
from radius_totp.crypto import SecretCipher
from radius_totp.local_auth import LocalPasswordAuthenticator
from radius_totp.radius_server import run_radius_server
from radius_totp.storage import PostgresUserStore
from radius_totp.totp import build_otpauth_uri, generate_secret, verify_totp


def build_auth_service(settings: Settings) -> AuthService:
    store = PostgresUserStore(settings.database_dsn)
    cipher = SecretCipher(settings.fernet_key)
    if settings.auth_backend == "local":
        password_authenticator = LocalPasswordAuthenticator(settings.local_users)
    else:
        password_authenticator = ActiveDirectoryAuthenticator(
            ActiveDirectoryConfig(
                server=settings.ad_server,
                port=settings.ad_port,
                use_ssl=settings.ad_use_ssl,
                start_tls=settings.ad_start_tls,
                tls_validate=settings.ad_tls_validate,
                base_dn=settings.ad_base_dn,
                user_upn_suffix=settings.ad_user_upn_suffix,
                bind_dn=settings.ad_bind_dn,
                bind_password=settings.ad_bind_password,
            )
        )
    return AuthService(
        store=store,
        password_authenticator=password_authenticator,
        cipher=cipher,
        otp_valid_window=settings.otp_valid_window,
        enable_password_otp=settings.enable_password_otp,
        enable_access_challenge=settings.enable_access_challenge,
    )


def save_qr(uri: str, path: Path) -> None:
    image = qrcode.make(uri)
    image.save(path)


def cmd_serve(args: argparse.Namespace) -> int:
    settings = load_settings(args.env)
    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    run_radius_server(settings, build_auth_service(settings))
    return 0


def cmd_enroll(args: argparse.Namespace) -> int:
    settings = load_settings(args.env)
    store = PostgresUserStore(settings.database_dsn)
    cipher = SecretCipher(settings.fernet_key)
    secret = generate_secret()
    uri = build_otpauth_uri(secret, args.username, settings.otp_issuer)
    qr_path = Path(args.qr_path or f"{args.username}.png")
    save_qr(uri, qr_path)

    print(f"OTP URI: {uri}")
    print(f"QR code written to: {qr_path}")
    code = args.confirm_code or getpass.getpass("Enter test OTP code: ")
    result = verify_totp(secret, code, last_used_timestep=None, valid_window=settings.otp_valid_window)
    if not result.ok:
        store.log_auth(args.username, "cli", "reject", f"enroll_{result.reason}", None)
        print(f"Enrollment failed: {result.reason}")
        return 1

    store.upsert_user_secret(args.username, cipher.encrypt(secret), enabled=True)
    store.log_auth(args.username, "cli", "accept", "enroll_ok", None)
    print(f"2FA enabled for {args.username}")
    return 0


def cmd_show_qr(args: argparse.Namespace) -> int:
    settings = load_settings(args.env)
    store = PostgresUserStore(settings.database_dsn)
    cipher = SecretCipher(settings.fernet_key)
    user = store.get_user(args.username)
    if user is None or not user.secret_encrypted:
        print(f"No TOTP secret found for {args.username}")
        return 1

    secret = cipher.decrypt(user.secret_encrypted)
    uri = build_otpauth_uri(secret, user.username, settings.otp_issuer)
    qr_path = Path(args.qr_path or f"{args.username}.png")
    save_qr(uri, qr_path)
    store.log_auth(args.username, "cli", "accept", "show_qr", None)
    print(f"QR code written to: {qr_path}")
    print(f"OTP URI: {uri}")
    return 0


def cmd_reset(args: argparse.Namespace) -> int:
    settings = load_settings(args.env)
    store = PostgresUserStore(settings.database_dsn)
    store.reset_user(args.username)
    store.log_auth(args.username, "cli", "accept", "reset", None)
    print(f"2FA reset for {args.username}")
    return 0


def cmd_set_enabled(args: argparse.Namespace) -> int:
    settings = load_settings(args.env)
    store = PostgresUserStore(settings.database_dsn)
    enabled = args.command == "enable"
    store.set_enabled(args.username, enabled)
    store.log_auth(args.username, "cli", "accept", "enable" if enabled else "disable", None)
    print(f"2FA {'enabled' if enabled else 'disabled'} for {args.username}")
    return 0


def cmd_test_radius(args: argparse.Namespace) -> int:
    password = args.password
    if password is None:
        password = getpass.getpass("Password: ")
    if args.otp is not None:
        password = f"{password}{args.otp}"

    request = packet.AuthPacket(
        code=packet.AccessRequest,
        secret=args.secret.encode("utf-8"),
        dict=Dictionary(args.dictionary),
    )
    request.AddAttribute("User-Name", args.username)
    request["User-Password"] = request.PwCrypt(password)

    try:
        reply = send_radius_request(request, args.server, args.port, args.timeout, args.retries)
    except Exception as exc:
        print(f"RADIUS request failed: {exc}")
        return 2

    code_names = {
        packet.AccessAccept: "Access-Accept",
        packet.AccessReject: "Access-Reject",
        packet.AccessChallenge: "Access-Challenge",
    }
    print(code_names.get(reply.code, f"RADIUS code {reply.code}"))
    if "Reply-Message" in reply:
        for message in reply["Reply-Message"]:
            print(f"Reply-Message: {message}")
    return 0 if reply.code == packet.AccessAccept else 1


def send_radius_request(
    request: packet.AuthPacket,
    server: str,
    port: int,
    timeout: float,
    retries: int,
) -> packet.AuthPacket:
    last_error: Exception | None = None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        for _ in range(retries):
            try:
                sock.sendto(request.RequestPacket(), (server, port))
                raw_reply, _ = sock.recvfrom(4096)
                reply = request.CreateReply(packet=raw_reply)
                if request.VerifyReply(reply, raw_reply):
                    reply.request_authenticator = request.authenticator
                    return reply
            except socket.timeout as exc:
                last_error = exc
            except packet.PacketError as exc:
                last_error = exc
    if last_error is not None:
        raise TimeoutError(f"No valid RADIUS reply after {retries} retries") from last_error
    raise TimeoutError(f"No valid RADIUS reply after {retries} retries")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="radius-totp")
    parser.add_argument("--env", help="Path to .env file", default=None)
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve = subparsers.add_parser("serve", help="Run RADIUS authentication service")
    serve.add_argument("--log-level", default="INFO")
    serve.set_defaults(func=cmd_serve)

    enroll = subparsers.add_parser("enroll", help="Enroll a user and enable 2FA")
    enroll.add_argument("username")
    enroll.add_argument("--qr-path")
    enroll.add_argument("--confirm-code")
    enroll.set_defaults(func=cmd_enroll)

    show_qr = subparsers.add_parser("show-qr", help="Regenerate QR code for an enrolled user")
    show_qr.add_argument("username")
    show_qr.add_argument("--qr-path")
    show_qr.set_defaults(func=cmd_show_qr)

    reset = subparsers.add_parser("reset", help="Reset user 2FA binding")
    reset.add_argument("username")
    reset.set_defaults(func=cmd_reset)

    enable = subparsers.add_parser("enable", help="Enable 2FA for a user")
    enable.add_argument("username")
    enable.set_defaults(func=cmd_set_enabled)

    disable = subparsers.add_parser("disable", help="Disable 2FA for a user")
    disable.add_argument("username")
    disable.set_defaults(func=cmd_set_enabled)

    test_radius = subparsers.add_parser("test-radius", help="Send a test RADIUS Access-Request")
    test_radius.add_argument("--server", required=True, help="RADIUS server IP or DNS name")
    test_radius.add_argument("--secret", required=True, help="RADIUS shared secret")
    test_radius.add_argument("--username", required=True)
    test_radius.add_argument("--password", help="Password or password part when --otp is used")
    test_radius.add_argument("--otp", help="Optional separate TOTP code; appended to password for password+otp mode")
    test_radius.add_argument("--port", type=int, default=1812)
    test_radius.add_argument("--dictionary", default="radius/dictionary")
    test_radius.add_argument("--timeout", type=float, default=5.0)
    test_radius.add_argument("--retries", type=int, default=3)
    test_radius.set_defaults(func=cmd_test_radius)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
