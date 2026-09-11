"""Resize requests are signalled in band on the input pipe, so the relay
has to pull them out of the keystroke stream without corrupting it."""

from __future__ import annotations

from sbx.process import RESIZE_OSC, split_resize_requests


def resize(cols: int, rows: int) -> bytes:
    return f"\x1b]9999;{cols};{rows}\x07".encode()


def test_plain_input_passes_through():
    assert split_resize_requests(b"ls -l\r") == (b"ls -l\r", [], b"")


def test_empty_input():
    assert split_resize_requests(b"") == (b"", [], b"")


def test_resize_is_extracted_and_stripped():
    payload, resizes, held = split_resize_requests(resize(80, 24))
    assert payload == b""
    assert resizes == [(80, 24)]
    assert held == b""


def test_resize_stripped_from_surrounding_keystrokes():
    data = b"abc" + resize(100, 40) + b"def"
    assert split_resize_requests(data) == (b"abcdef", [(100, 40)], b"")


def test_multiple_resizes_in_order():
    data = resize(80, 24) + b"x" + resize(120, 30)
    payload, resizes, held = split_resize_requests(data)
    assert payload == b"x"
    assert resizes == [(80, 24), (120, 30)]


def test_split_across_reads_never_corrupts_keystrokes():
    """A pipe read can land anywhere in the stream.  Wherever it cuts, the
    user's keystrokes must survive intact: a missed resize corrects itself
    on the next one, mangled input does not."""
    whole = b"hi" + resize(90, 25) + b"bye"
    for cut in range(len(whole) + 1):
        payload1, _, held = split_resize_requests(whole[:cut])
        payload2, _, held2 = split_resize_requests(held + whole[cut:])

        assert held2 == b"", f"nothing should remain held at cut {cut}"
        combined = RESIZE_OSC.sub(b"", payload1 + payload2)
        assert combined == b"hibye", f"corrupted at cut {cut}"


def test_resize_survives_a_split_after_the_osc_introducer():
    """Fragments are held from the ESC-] introducer onwards, which no
    keystroke produces — so a split anywhere inside the sequence keeps
    both the resize and the surrounding input."""
    whole = b"hi" + resize(90, 25) + b"bye"
    introducer = whole.index(b"\x1b]") + 2
    for cut in range(introducer, len(whole) + 1):
        payload1, resizes1, held = split_resize_requests(whole[:cut])
        payload2, resizes2, held2 = split_resize_requests(held + whole[cut:])

        assert resizes1 + resizes2 == [(90, 25)], f"lost resize at cut {cut}"
        assert payload1 + payload2 == b"hibye", f"corrupted at cut {cut}"


def test_lone_trailing_escape_is_forwarded_not_held():
    """A bare ESC is a real keystroke.  Holding it back to see whether a
    resize follows would stall Esc in interactive programs, so it goes
    straight through — accepting that a resize split at exactly that byte
    reaches the shell as a stray escape and is not applied."""
    payload, resizes, held = split_resize_requests(b"hi\x1b")
    assert payload == b"hi\x1b"
    assert resizes == []
    assert held == b""


def test_unrelated_osc_sequence_is_forwarded():
    """A title-setting escape is not ours and must reach the shell."""
    data = b"\x1b]0;some title\x07ls"
    assert split_resize_requests(data) == (data, [], b"")


def test_partial_unrelated_osc_is_held_not_truncated():
    payload, resizes, held = split_resize_requests(b"ls\x1b]0;tit")
    assert payload == b"ls"
    assert resizes == []
    assert held == b"\x1b]0;tit"
    # and completing it forwards the whole sequence
    payload2, resizes2, held2 = split_resize_requests(held + b"le\x07")
    assert payload2 == b"\x1b]0;title\x07"
    assert resizes2 == []
    assert held2 == b""
