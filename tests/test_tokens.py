import ctypes
import os
import pytest

from sbx import winapi
from sbx.tokens import create_sandbox_token
from sbx.identity import generate_sid


def _get_current_user_sid() -> int:
    token = winapi.open_process_token(winapi.TOKEN_QUERY)
    try:
        length = ctypes.wintypes.DWORD()
        TOKEN_USER = 1
        winapi.advapi32.GetTokenInformation(
            token, TOKEN_USER, None, 0, ctypes.byref(length)
        )
        buf = (ctypes.c_ubyte * length.value)()
        ok = winapi.advapi32.GetTokenInformation(
            token, TOKEN_USER, buf, length.value, ctypes.byref(length)
        )
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())
        sid_ptr = ctypes.c_void_p.from_buffer_copy(buf).value
        sid_str = winapi.sid_to_string(sid_ptr)
        return winapi.string_to_sid(sid_str)
    finally:
        winapi.close_handle(token)


@pytest.mark.integration
def test_restricted_sids():
    sid_str = generate_sid()
    token = create_sandbox_token(sid_str)
    try:
        restricted = winapi.get_token_restricted_sids(token)
        assert sid_str in restricted
        assert winapi.BUILTIN_USERS_SID in restricted
        assert winapi.EVERYONE_SID in restricted
    finally:
        winapi.close_handle(token)


@pytest.mark.integration
def test_can_read_acled_path(tmp_path):
    sid_str = generate_sid()
    test_dir = tmp_path / "allowed_dir"
    test_dir.mkdir()
    test_file = test_dir / "data.txt"
    test_file.write_text("hello")

    sandbox_sid_ptr = winapi.string_to_sid(sid_str)
    user_sid_ptr = _get_current_user_sid()
    try:
        winapi.set_protected_dacl(
            str(test_dir),
            [
                (user_sid_ptr, winapi.FILE_ALL_ACCESS),
                (sandbox_sid_ptr, winapi.FILE_ALL_ACCESS),
            ],
        )
        winapi.set_protected_dacl(
            str(test_file),
            [
                (user_sid_ptr, winapi.FILE_ALL_ACCESS),
                (sandbox_sid_ptr, winapi.FILE_ALL_ACCESS),
            ],
        )
    finally:
        winapi.kernel32.LocalFree(sandbox_sid_ptr)
        winapi.kernel32.LocalFree(user_sid_ptr)

    token = create_sandbox_token(sid_str)
    try:
        winapi.impersonate_token(token)
        try:
            content = test_file.read_text()
            assert content == "hello"
        finally:
            winapi.revert_to_self()
    finally:
        winapi.close_handle(token)


@pytest.mark.integration
def test_cannot_read_non_acled_path(tmp_path):
    sid_str = generate_sid()
    denied_dir = tmp_path / "denied_dir"
    denied_dir.mkdir()
    denied_file = denied_dir / "secret.txt"
    denied_file.write_text("secret")

    user_sid_ptr = _get_current_user_sid()
    try:
        winapi.set_protected_dacl(
            str(denied_dir),
            [(user_sid_ptr, winapi.FILE_ALL_ACCESS)],
        )
        winapi.set_protected_dacl(
            str(denied_file),
            [(user_sid_ptr, winapi.FILE_ALL_ACCESS)],
        )
    finally:
        winapi.kernel32.LocalFree(user_sid_ptr)

    token = create_sandbox_token(sid_str)
    try:
        winapi.impersonate_token(token)
        try:
            with pytest.raises(PermissionError):
                denied_file.read_text()
        finally:
            winapi.revert_to_self()
    finally:
        winapi.close_handle(token)


@pytest.mark.integration
def test_no_dangerous_privileges():
    sid_str = generate_sid()
    token = create_sandbox_token(sid_str)
    try:
        enabled = winapi.get_token_enabled_privilege_count(token)
        assert enabled <= 1
    finally:
        winapi.close_handle(token)
