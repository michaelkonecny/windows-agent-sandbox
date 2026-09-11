import os
import re
import pytest

from sbx import identity, winapi


def test_sid_format():
    sid = identity.generate_sid()
    parts = sid.split("-")
    assert parts[0] == "S"
    assert parts[1] == "1"
    assert parts[2] == "42"
    assert len(parts) == 7


def test_sid_uniqueness():
    a = identity.generate_sid()
    b = identity.generate_sid()
    assert a != b


def test_dpapi_roundtrip(tmp_path):
    creds_path = tmp_path / "creds.json"
    identity.store_credentials("sbx-user", "s3cret-p@ss!", creds_path)
    user, pw = identity.get_credentials(creds_path)
    assert user == "sbx-user"
    assert pw == "s3cret-p@ss!"


@pytest.mark.elevation
def test_install_user_idempotent():
    try:
        name = identity.install_user()
        assert name == identity.SANDBOX_USER
        assert winapi.user_exists(identity.SANDBOX_USER)
        name2 = identity.install_user()
        assert name2 == identity.SANDBOX_USER
    finally:
        winapi.delete_user(identity.SANDBOX_USER)


@pytest.mark.elevation
def test_uninstall_user():
    identity.install_user()
    identity.uninstall_user()
    assert not winapi.user_exists(identity.SANDBOX_USER)
