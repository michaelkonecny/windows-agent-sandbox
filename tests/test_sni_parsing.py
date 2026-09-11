"""The two pure functions the network policy rests on.

`parse_sni` reads a hostname straight out of an attacker-controlled byte
stream, and `is_domain_allowed` decides on it. Both are worth pinning
precisely: a parser that returns a *wrong* hostname is far worse than one
that returns nothing, because the allowlist is then asked the wrong
question.
"""

from __future__ import annotations

import pytest

from sbx.config import NetworkPreset
from sbx.proxy import NetworkPolicy, is_domain_allowed, parse_sni


def client_hello(
    hostname: str | None = "api.anthropic.com",
    session_id: bytes = b"",
    ciphers: bytes = b"\x00\xff",
    leading_extensions: bytes = b"",
    name_type: int = 0x00,
    declared_name_len: int | None = None,
) -> bytes:
    """A TLS ClientHello, with the knobs a real one varies by."""
    extensions = leading_extensions
    if hostname is not None:
        host = hostname.encode("utf-8")
        length = len(host) if declared_name_len is None else declared_name_len
        entry = bytes([name_type]) + length.to_bytes(2, "big") + host
        name_list = len(entry).to_bytes(2, "big") + entry
        extensions += b"\x00\x00" + len(name_list).to_bytes(2, "big") + name_list

    body = (
        b"\x03\x03"
        + b"\x00" * 32
        + bytes([len(session_id)]) + session_id
        + len(ciphers).to_bytes(2, "big") + ciphers
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big") + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def other_extension(ext_type: int, payload: bytes) -> bytes:
    return ext_type.to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload


# ── parse_sni ────────────────────────────────────────────────


def test_plain_client_hello():
    assert parse_sni(client_hello("api.anthropic.com")) == "api.anthropic.com"


def test_session_id_is_skipped():
    """Real clients resume sessions, so the field is rarely empty."""
    assert parse_sni(client_hello(session_id=b"\xab" * 32)) == "api.anthropic.com"


def test_many_cipher_suites_are_skipped():
    assert parse_sni(client_hello(ciphers=b"\x13\x01\x13\x02\x13\x03\xc0\x2f")) == (
        "api.anthropic.com"
    )


def test_sni_found_after_other_extensions():
    """SNI is rarely the first extension in a real ClientHello."""
    leading = other_extension(0x002B, b"\x02\x03\x04") + other_extension(
        0x000A, b"\x00\x04\x00\x17\x00\x18"
    )
    assert parse_sni(client_hello(leading_extensions=leading)) == (
        "api.anthropic.com"
    )


def test_no_sni_extension():
    assert parse_sni(client_hello(hostname=None)) is None


def test_non_hostname_name_type_is_not_returned():
    assert parse_sni(client_hello(name_type=0x01)) is None


def test_not_a_handshake_record():
    assert parse_sni(b"\x17\x03\x03\x00\x05hello") is None


def test_empty_and_tiny_inputs():
    assert parse_sni(b"") is None
    assert parse_sni(b"\x00\x01\x02") is None
    assert parse_sni(b"\x16\x03\x01\x00\x00") is None


def test_truncated_at_every_length_never_raises_or_lies():
    """A short read must yield None, not a prefix of the hostname.

    Returning a prefix is the dangerous failure: a name like
    `api.anthropic.com.evil.test` cut short reads as an allowed host, so
    the allowlist would be asked about a domain nobody sent.
    """
    whole = client_hello("api.anthropic.com.evil.test")
    for cut in range(len(whole)):
        result = parse_sni(whole[:cut])
        assert result in (None, "api.anthropic.com.evil.test"), (
            f"truncating to {cut} bytes produced {result!r}"
        )


def test_a_name_longer_than_the_buffer_is_rejected():
    """The length field is attacker-controlled and need not match."""
    data = client_hello("api.anthropic.com", declared_name_len=500)
    assert parse_sni(data) is None


def test_non_ascii_hostname_does_not_raise():
    assert parse_sni(client_hello("héllo.example")) is None


# ── is_domain_allowed ────────────────────────────────────────


CLAUDE_ONLY = NetworkPolicy(NetworkPreset.claude_api_only)


def test_preset_all_allows_anything():
    assert is_domain_allowed("evil.test", NetworkPolicy(NetworkPreset.all))


def test_preset_none_allows_nothing():
    assert not is_domain_allowed(
        "api.anthropic.com", NetworkPolicy(NetworkPreset.none)
    )


def test_exact_and_subdomain_match():
    assert is_domain_allowed("api.anthropic.com", CLAUDE_ONLY)


def test_a_sibling_domain_does_not_match():
    """The check must not be a bare suffix test, or this would pass."""
    assert not is_domain_allowed("evil-anthropic.com", CLAUDE_ONLY)
    assert not is_domain_allowed("notanthropic.com", CLAUDE_ONLY)


def test_the_allowed_name_as_a_subdomain_of_someone_else():
    assert not is_domain_allowed("api.anthropic.com.evil.test", CLAUDE_ONLY)


def test_unrelated_domain():
    assert not is_domain_allowed("example.com", CLAUDE_ONLY)


def test_custom_allowlist_replaces_the_default():
    policy = NetworkPolicy(NetworkPreset.claude_api_only, ["example.com"])
    assert is_domain_allowed("example.com", policy)
    assert is_domain_allowed("cdn.example.com", policy)
    assert not is_domain_allowed("api.anthropic.com", policy)


@pytest.mark.parametrize("domain", ["API.ANTHROPIC.COM", "Api.Anthropic.Com"])
def test_hostname_case_is_ignored(domain):
    """DNS is case-insensitive, and a client may send any casing."""
    assert is_domain_allowed(domain, CLAUDE_ONLY)


def test_trailing_dot_is_ignored():
    """`api.anthropic.com.` is the same host, fully qualified."""
    assert is_domain_allowed("api.anthropic.com.", CLAUDE_ONLY)


def test_empty_domain_is_denied():
    assert not is_domain_allowed("", CLAUDE_ONLY)
