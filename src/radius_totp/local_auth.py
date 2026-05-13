from __future__ import annotations

import hmac


class LocalPasswordAuthenticator:
    def __init__(self, users: tuple[tuple[str, str], ...]) -> None:
        self._users = dict(users)

    def authenticate(self, username: str, password: str) -> bool:
        expected = self._users.get(username.lower())
        if expected is None:
            return False
        return hmac.compare_digest(expected.encode("utf-8"), password.encode("utf-8"))
