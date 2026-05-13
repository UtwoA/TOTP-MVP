from __future__ import annotations

from radius_totp.config import parse_local_users, parse_radius_clients


def test_parse_radius_clients() -> None:
    clients = parse_radius_clients("10.0.0.1:secret1:cisco,10.0.0.2:secret2")

    assert clients[0].host == "10.0.0.1"
    assert clients[0].secret == "secret1"
    assert clients[0].name == "cisco"
    assert clients[1].name == "10.0.0.2"


def test_parse_local_users() -> None:
    users = parse_local_users("demo.user:DemoPassword123, admin:AnotherPassword")

    assert users == (("demo.user", "DemoPassword123"), ("admin", "AnotherPassword"))
