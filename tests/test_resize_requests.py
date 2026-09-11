"""Resize requests are signalled in band on the input pipe, so the relay
has to pull them out of the keystroke stream without corrupting it."""

from __future__ import annotations

from sbx.process import RESIZE_OSC, resize_request as resize, split_resize_requests


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


def test_partial_unrelated_osc_is_forwarded_immediately():
    """Only a fragment that could still become a resize request is worth
    holding.  Anything else goes straight through: forwarding it in two
    pieces costs nothing, since the shell reads a byte stream."""
    data = b"ls\x1b]0;tit"
    assert split_resize_requests(data) == (data, [], b"")


def test_a_fragment_is_never_held_indefinitely():
    """The bug this guards against: hold anything starting with ESC-] and
    a stray Alt+] silently swallows every later keystroke, leaving the
    sandbox's keyboard dead with nothing logged."""
    payload, resizes, held = split_resize_requests(b"\x1b]")
    assert held == b"\x1b]", "a real resize prefix should still be held"

    # Whatever arrives next either completes the request or frees it.
    payload, resizes, held = split_resize_requests(held + b"hello world")
    assert held == b""
    assert payload == b"\x1b]hello world"
    assert resizes == []


def test_a_long_run_of_digits_is_not_held_forever():
    """Bounded even when every byte looks plausible."""
    fragment = b"\x1b]9999;" + b"1" * 64
    payload, resizes, held = split_resize_requests(fragment)
    assert held == b""
    assert payload == fragment
