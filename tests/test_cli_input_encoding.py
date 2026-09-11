"""Console input events to sandbox bytes.

Built from real INPUT_RECORD structures rather than stand-ins, so the
field names and the union layout are covered too.
"""

from __future__ import annotations

from sbx import winapi
from sbx.cli import encode_console_records
from sbx.process import resize_request


def key(char: str, down: bool = True, repeats: int = 1) -> winapi.INPUT_RECORD:
    record = winapi.INPUT_RECORD()
    record.EventType = winapi.KEY_EVENT
    record.Event.KeyEvent.bKeyDown = down
    record.Event.KeyEvent.UnicodeChar = char
    record.Event.KeyEvent.wRepeatCount = repeats
    return record


def resize_event() -> winapi.INPUT_RECORD:
    record = winapi.INPUT_RECORD()
    record.EventType = winapi.WINDOW_BUFFER_SIZE_EVENT
    return record


def no_size():
    raise AssertionError("terminal size should not be consulted")


def test_no_records_yields_nothing():
    assert encode_console_records([], no_size) == b""


def test_typed_characters_are_forwarded():
    records = [key("l"), key("s"), key("\r")]
    assert encode_console_records(records, no_size) == b"ls\r"


def test_key_up_events_are_ignored():
    """Otherwise every keystroke would be sent twice."""
    records = [key("a"), key("a", down=False)]
    assert encode_console_records(records, no_size) == b"a"


def test_modifier_only_keys_are_ignored():
    """Shift and friends arrive as key-downs carrying no character."""
    assert encode_console_records([key("\x00")], no_size) == b""


def test_ctrl_c_is_forwarded_as_a_byte():
    """Ctrl+C must reach the sandbox shell rather than interrupt the host."""
    assert encode_console_records([key("\x03")], no_size) == b"\x03"


def test_escape_sequence_characters_pass_through_in_order():
    """VT input mode delivers an arrow key as ESC [ A across records."""
    records = [key("\x1b"), key("["), key("A")]
    assert encode_console_records(records, no_size) == b"\x1b[A"


def test_non_ascii_is_utf8_encoded():
    assert encode_console_records([key("é")], no_size) == "é".encode()


def test_resize_event_emits_a_resize_request():
    out = encode_console_records([resize_event()], lambda: (100, 40))
    assert out == resize_request(100, 40)


def test_resize_is_interleaved_with_keystrokes_in_order():
    records = [key("a"), resize_event(), key("b")]
    out = encode_console_records(records, lambda: (80, 24))
    assert out == b"a" + resize_request(80, 24) + b"b"


def test_unavailable_terminal_size_is_skipped():
    records = [key("a"), resize_event(), key("b")]
    assert encode_console_records(records, lambda: None) == b"ab"


def test_a_held_key_is_repeated():
    """The console coalesces auto-repeat into one record with a count;
    ignoring it would swallow every repeat but the first."""
    assert encode_console_records([key("x", repeats=5)], no_size) == b"xxxxx"


def test_a_zero_repeat_count_still_sends_the_key():
    assert encode_console_records([key("x", repeats=0)], no_size) == b"x"
