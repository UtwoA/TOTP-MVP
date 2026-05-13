from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass

from pyrad import packet, server
from pyrad.dictionary import Dictionary

from radius_totp.auth import AuthService
from radius_totp.config import Settings

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class ChallengeState:
    username: str
    radius_client: str
    expires_at: float


class RadiusTotpServer(server.Server):
    def __init__(self, settings: Settings, auth_service: AuthService) -> None:
        super().__init__(
            addresses=[settings.radius_listen_host],
            authport=settings.radius_auth_port,
            dict=Dictionary(settings.radius_dictionary),
        )
        self._auth_service = auth_service
        self._settings = settings
        self._states: dict[str, ChallengeState] = {}

        for radius_client in settings.radius_clients:
            self.hosts[radius_client.host] = server.RemoteHost(
                radius_client.host,
                radius_client.secret.encode("utf-8"),
                radius_client.name,
            )

    def HandleAuthPacket(self, pkt: packet.AuthPacket) -> None:
        username = self._first_attr(pkt, "User-Name")
        radius_client = self._client_name(pkt)
        reply = self.CreateReplyPacket(pkt)

        try:
            if not username:
                self._reject(reply, pkt, "Missing username")
                return

            if self._has_attr(pkt, "State"):
                otp = self._password(pkt)
                state_token = self._first_attr(pkt, "State")
                result = self._handle_challenge_response(username, otp, state_token, radius_client)
            else:
                password = self._password(pkt)
                if password is None:
                    self._reject(reply, pkt, "Missing password")
                    return
                result = self._auth_service.authenticate_initial(username, password, radius_client)

            if result.ok:
                reply.code = packet.AccessAccept
                reply.AddAttribute("Reply-Message", "Access granted")
            elif result.requires_challenge:
                state_token = self._new_state(username, radius_client)
                reply.code = packet.AccessChallenge
                reply.AddAttribute("Reply-Message", "Enter OTP code")
                reply.AddAttribute("State", state_token)
            else:
                reply.code = packet.AccessReject
                reply.AddAttribute("Reply-Message", "Access denied")
        except Exception:
            LOGGER.exception("Unexpected RADIUS authentication error")
            reply.code = packet.AccessReject
            reply.AddAttribute("Reply-Message", "Access denied")
        finally:
            self.SendReplyPacket(pkt.fd, reply)

    def _handle_challenge_response(self, username: str, otp: str | None, state_token: str | None, radius_client: str):
        if not otp or not state_token:
            return self._auth_service.authenticate_otp(username, "", radius_client)

        self._purge_states()
        state = self._states.pop(state_token, None)
        if state is None or state.username.lower() != username.lower() or state.radius_client != radius_client:
            return self._reject_result("invalid_challenge_state", username, radius_client)

        return self._auth_service.authenticate_otp(username, otp, radius_client)

    def _reject_result(self, reason: str, username: str, radius_client: str):
        return self._auth_service.reject(username, reason, radius_client)

    def _new_state(self, username: str, radius_client: str) -> str:
        token = secrets.token_urlsafe(24)
        self._states[token] = ChallengeState(
            username=username,
            radius_client=radius_client,
            expires_at=time.time() + 120,
        )
        return token

    def _purge_states(self) -> None:
        now = time.time()
        expired = [token for token, state in self._states.items() if state.expires_at < now]
        for token in expired:
            self._states.pop(token, None)

    def _reject(self, reply: packet.Packet, pkt: packet.AuthPacket, message: str) -> None:
        LOGGER.info("Rejecting RADIUS packet: %s", message)
        reply.code = packet.AccessReject
        reply.AddAttribute("Reply-Message", "Access denied")

    def _password(self, pkt: packet.AuthPacket) -> str | None:
        if not self._has_attr(pkt, "User-Password"):
            return None
        try:
            encrypted_password = pkt["User-Password"][0]
            if isinstance(encrypted_password, str):
                encrypted_password = encrypted_password.encode("latin-1")
            return pkt.PwDecrypt(encrypted_password)
        except Exception:
            LOGGER.exception("Failed to decrypt RADIUS User-Password")
            return None

    def _first_attr(self, pkt: packet.AuthPacket, name: str) -> str | None:
        if not self._has_attr(pkt, name):
            return None
        value = pkt[name][0]
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def _has_attr(self, pkt: packet.AuthPacket, name: str) -> bool:
        try:
            return name in pkt and bool(pkt[name])
        except KeyError:
            return False

    def _client_name(self, pkt: packet.AuthPacket) -> str:
        host = getattr(pkt, "source", ("unknown",))[0]
        remote = self.hosts.get(host)
        return remote.name if remote is not None else host


def run_radius_server(settings: Settings, auth_service: AuthService) -> None:
    radius_server = RadiusTotpServer(settings, auth_service)
    LOGGER.info("Starting RADIUS server on %s:%s", settings.radius_listen_host, settings.radius_auth_port)
    radius_server.Run()
