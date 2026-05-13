from __future__ import annotations

from cryptography.fernet import Fernet

from radius_totp.crypto import SecretCipher


def test_secret_cipher_encrypts_without_plaintext_leak() -> None:
    secret = "JBSWY3DPEHPK3PXP"
    cipher = SecretCipher(Fernet.generate_key().decode("utf-8"))

    encrypted = cipher.encrypt(secret)

    assert secret.encode("utf-8") not in encrypted
    assert cipher.decrypt(encrypted) == secret
