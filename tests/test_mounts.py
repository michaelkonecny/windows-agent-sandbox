import pytest
from pathlib import Path

from sbx import winapi
from sbx.identity import generate_sid
from sbx.mounts import MountSpec, create, destroy


@pytest.fixture
def user_sid():
    """Stands in for sbx-user's SID.

    mounts resolves the real account by name, but these tests must not
    depend on the machine having it — test_identity deletes the account —
    so they supply a synthetic SID instead.  What the second ACE actually
    buys is covered by the system tests, which run as the real account.
    """
    return generate_sid()


@pytest.mark.elevation
def test_create_bind_links(tmp_path, user_sid):
    source = tmp_path / "backing"
    source.mkdir()
    (source / "data.txt").write_text("content")

    ws = tmp_path / "workspace"
    meta = tmp_path / "meta"
    sid = generate_sid()
    specs = [MountSpec(source=source, target="repo", sandbox_sid=sid)]

    create("test-sbx", specs, workspace_root=ws, meta_root=meta, user_sid=user_sid)
    try:
        target = ws / "test-sbx" / "repo"
        assert target.exists()
        assert (target / "data.txt").read_text() == "content"
    finally:
        destroy("test-sbx", workspace_root=ws, meta_root=meta, user_sid=user_sid)


@pytest.mark.elevation
def test_acls_set(tmp_path, user_sid):
    source = tmp_path / "backing"
    source.mkdir()
    sid_str = generate_sid()

    ws = tmp_path / "workspace"
    meta = tmp_path / "meta"
    specs = [MountSpec(source=source, target="code", sandbox_sid=sid_str)]

    create("test-sbx", specs, workspace_root=ws, meta_root=meta, user_sid=user_sid)
    try:
        token = winapi.create_sandbox_token_from_sid(sid_str)
    except AttributeError:
        from sbx.tokens import create_sandbox_token
        token = create_sandbox_token(sid_str)

    try:
        winapi.impersonate_token(token)
        try:
            assert source.exists()
        finally:
            winapi.revert_to_self()
    finally:
        winapi.close_handle(token)
        destroy("test-sbx", workspace_root=ws, meta_root=meta, user_sid=user_sid)


@pytest.mark.elevation
def test_destroy_removes_bind_links(tmp_path, user_sid):
    source = tmp_path / "backing"
    source.mkdir()

    ws = tmp_path / "workspace"
    meta = tmp_path / "meta"
    sid = generate_sid()
    specs = [MountSpec(source=source, target="repo", sandbox_sid=sid)]

    create("test-sbx", specs, workspace_root=ws, meta_root=meta, user_sid=user_sid)
    target = ws / "test-sbx" / "repo"
    assert target.exists()

    destroy("test-sbx", workspace_root=ws, meta_root=meta, user_sid=user_sid)
    assert not target.exists()


@pytest.mark.elevation
def test_destroy_cleans_acls(tmp_path, user_sid):
    source = tmp_path / "backing"
    source.mkdir()
    sid_str = generate_sid()

    ws = tmp_path / "workspace"
    meta = tmp_path / "meta"
    specs = [MountSpec(source=source, target="code", sandbox_sid=sid_str)]

    create("test-sbx", specs, workspace_root=ws, meta_root=meta, user_sid=user_sid)
    destroy("test-sbx", workspace_root=ws, meta_root=meta, user_sid=user_sid)

    from sbx.tokens import create_sandbox_token
    token = create_sandbox_token(sid_str)
    try:
        winapi.impersonate_token(token)
        try:
            with pytest.raises(PermissionError):
                (source / "testfile.txt").write_text("should fail")
        finally:
            winapi.revert_to_self()
    finally:
        winapi.close_handle(token)


@pytest.mark.elevation
def test_leftover_cleanup(tmp_path, user_sid):
    source = tmp_path / "backing"
    source.mkdir()
    (source / "data.txt").write_text("content")

    ws = tmp_path / "workspace"
    meta = tmp_path / "meta"
    sid = generate_sid()
    specs = [MountSpec(source=source, target="repo", sandbox_sid=sid)]

    target = ws / "test-sbx" / "repo"
    target.mkdir(parents=True)
    winapi.create_bind_link(str(target), str(source))

    create("test-sbx", specs, workspace_root=ws, meta_root=meta, user_sid=user_sid)
    try:
        assert (target / "data.txt").read_text() == "content"
    finally:
        destroy("test-sbx", workspace_root=ws, meta_root=meta, user_sid=user_sid)


@pytest.mark.elevation
def test_file_mount(tmp_path, user_sid):
    """The config example mounts a single file, not a directory.

    create makes every virtual path a directory before mapping it, which
    reads as though a file source would break — the bind filter maps the
    file over it regardless and the target reads back as the file.
    """
    backing = tmp_path / "backing"
    backing.mkdir()
    source = backing / "some-tool.json"
    source.write_text('{"hello": "from host"}', encoding="utf-8")

    ws = tmp_path / "workspace"
    meta = tmp_path / "meta"
    specs = [
        MountSpec(
            source=source,
            target="config/some-tool.json",
            sandbox_sid=generate_sid(),
        )
    ]

    create("test-sbx", specs, workspace_root=ws, meta_root=meta,
           user_sid=user_sid)
    try:
        target = ws / "test-sbx" / "config" / "some-tool.json"
        assert target.read_text(encoding="utf-8") == '{"hello": "from host"}'
    finally:
        destroy("test-sbx", workspace_root=ws, meta_root=meta,
                user_sid=user_sid)
