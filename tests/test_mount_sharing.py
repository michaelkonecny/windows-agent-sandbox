"""Two sandboxes may mount the same directory.

The per-sandbox synthetic SID is private, but the sbx-user ACE on a
backing path is shared, so destroying one sandbox must not revoke it
while another still mounts that directory — doing so would silently cost
the survivor access to its own mount.
"""

from __future__ import annotations

import json
from pathlib import Path

from sbx.mounts import _normalise, _sources_used_by_others


def write_meta(meta_root: Path, sandbox: str, sources: list[str]) -> None:
    meta_root.mkdir(parents=True, exist_ok=True)
    (meta_root / f"{sandbox}.json").write_text(
        json.dumps([
            {"source": s, "target": "repo", "sandbox_sid": "S-1-42-1-2-3-4"}
            for s in sources
        ]),
        encoding="utf-8",
    )


def test_no_other_sandboxes_means_nothing_is_shared(tmp_path):
    write_meta(tmp_path, "alpha", [r"C:\projects\one"])
    assert _sources_used_by_others("alpha", tmp_path) == set()


def test_a_source_mounted_by_another_sandbox_is_reported(tmp_path):
    write_meta(tmp_path, "alpha", [r"C:\projects\one"])
    write_meta(tmp_path, "beta", [r"C:\projects\one"])

    shared = _sources_used_by_others("alpha", tmp_path)
    assert _normalise(r"C:\projects\one") in shared


def test_paths_differing_only_in_spelling_still_match(tmp_path):
    """Windows paths are case-insensitive, so a mismatch here would revoke
    the shared ACE while beta is still using the directory."""
    write_meta(tmp_path, "alpha", [r"C:\Projects\One"])
    write_meta(tmp_path, "beta", [r"c:\projects\one"])

    assert _normalise(r"C:\Projects\One") in _sources_used_by_others(
        "alpha", tmp_path
    )


def test_unrelated_sources_are_not_reported(tmp_path):
    write_meta(tmp_path, "alpha", [r"C:\projects\one"])
    write_meta(tmp_path, "beta", [r"C:\projects\two"])

    assert _normalise(r"C:\projects\one") not in _sources_used_by_others(
        "alpha", tmp_path
    )


def test_unreadable_metadata_is_skipped(tmp_path):
    """A corrupt file must not abort the scan — the alternative is a
    teardown that stops halfway."""
    write_meta(tmp_path, "beta", [r"C:\projects\one"])
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")

    assert _sources_used_by_others("alpha", tmp_path) == {
        _normalise(r"C:\projects\one")
    }


def test_missing_metadata_directory(tmp_path):
    assert _sources_used_by_others("alpha", tmp_path / "absent") == set()
