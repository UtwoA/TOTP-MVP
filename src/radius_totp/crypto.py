from __future__ import annotations

from cryptography.fernet import Fernet


class SecretCipher:
    def __init__(self, key: str) -> None:
        self._fernet = Fernet(key.encode("utf-8"))

    def encrypt(self, secret: str) -> bytes:
        return self._fernet.encrypt(secret.encode("utf-8"))

    def decrypt(self, encrypted_secret: bytes) -> str:
        return self._fernet.decrypt(encrypted_secret).decode("utf-8")
