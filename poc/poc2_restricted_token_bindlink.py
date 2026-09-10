"""PoC 2 — Restricted token + bind link interaction.

Validates: a process running under a fully restricted token (not
WRITE_RESTRICTED) can traverse bind links when the synthetic SID
has ACLs on the backing path.

Approach — impersonation rather than subprocess, to isolate the
token/ACL question from process-launch complexity:
  1. Create a synthetic SID and a BUILTIN\\Users SID.
  2. Create a backing dir, ACL it for the synthetic SID (RW).
  3. Create a forbidden dir, set a protected DACL with only
     Administrators (no Users, no Everyone).
  4. Create a bind link: virtual dir -> backing dir.
  5. Create a fully restricted token with RestrictedSids =
     [synthetic_sid, users_sid].
  6. Impersonate the restricted token on the current thread.
  7. Verify: read/write through the bind link SUCCEEDS.
  8. Verify: read from the forbidden dir FAILS (PermissionError).
  9. Revert and clean up.

Why the restricted SID list has two entries:
  - synthetic_sid — gates access to the sandbox's own mounts.
  - users_sid (S-1-5-32-545) — lets the process reach system paths
    whose DACLs grant BUILTIN\\Users read access (C:\\Windows, etc.).
  The restricted-SID access check is an OR across the list, ANDed
  with the normal SID check.

Must be run elevated (admin).
"""

import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(__file__))
import winapi

TEST_ROOT = r"C:\sbx-poc2-test"
BACKING_DIR = rf"{TEST_ROOT}\backing"
VIRTUAL_DIR = rf"{TEST_ROOT}\virtual"
FORBIDDEN_DIR = rf"{TEST_ROOT}\forbidden"


def log(tag, msg):
    print(f"[{tag:5s}] {msg}")


def setup():
    if not winapi.is_elevated():
        sys.exit("ERROR: must run elevated (admin).")

    winapi.remove_bind_link(VIRTUAL_DIR)

    log("STEP", "Creating test directories...")
    for d in [BACKING_DIR, VIRTUAL_DIR, FORBIDDEN_DIR]:
        os.makedirs(d, exist_ok=True)

    with open(os.path.join(BACKING_DIR, "test.txt"), "w") as f:
        f.write("hello from backing")

    with open(os.path.join(FORBIDDEN_DIR, "secret.txt"), "w") as f:
        f.write("top secret")

    return create_sids_and_acls()


def create_sids_and_acls():
    log("STEP", "Creating synthetic SID...")
    synthetic_sid = winapi.create_synthetic_sid()
    synthetic_str = winapi.sid_to_string(synthetic_sid)
    log("OK", f"Synthetic SID: {synthetic_str}")

    log("STEP", "Creating BUILTIN\\Users SID...")
    users_sid = winapi.create_users_sid()
    users_str = winapi.sid_to_string(users_sid)
    log("OK", f"Users SID: {users_str}")

    log("STEP", "ACLing backing dir for synthetic SID (full control)...")
    winapi.grant_sid_access(BACKING_DIR, synthetic_sid)
    log("OK", "Backing dir ACL set.")

    log("STEP", "Setting protected DACL on forbidden dir (Administrators only)...")
    admin_sid = winapi.create_administrators_sid()
    winapi.set_protected_dacl_sid(
        FORBIDDEN_DIR,
        [(admin_sid, winapi.FILE_ALL_ACCESS)],
    )
    winapi.free_sid(admin_sid)
    log("OK", "Forbidden dir locked down.")

    log("STEP", "Creating bind link: virtual -> backing...")
    winapi.create_bind_link(VIRTUAL_DIR, BACKING_DIR)
    log("OK", f"Bind link: {VIRTUAL_DIR}  ->  {BACKING_DIR}")

    log("STEP", "Creating restricted token...")
    token = winapi.create_restricted_token([synthetic_sid, users_sid])
    log("OK", "Restricted token created (DISABLE_MAX_PRIVILEGE, not WRITE_RESTRICTED).")

    return synthetic_sid, users_sid, token


def test_read_via_bindlink(token):
    """Read test.txt through the bind link under the restricted token."""
    log("TEST", "Reading through bind link under restricted token...")
    winapi.impersonate_token(token)
    try:
        path = os.path.join(VIRTUAL_DIR, "test.txt")
        content = open(path).read()
        if content == "hello from backing":
            log("PASS", f'Read via bind link: got "{content}"')
            return True
        else:
            log("FAIL", f'Read via bind link: expected "hello from backing", got "{content}"')
            return False
    except PermissionError as e:
        log("FAIL", f"Read via bind link: PermissionError — {e}")
        return False
    except Exception as e:
        log("FAIL", f"Read via bind link: {type(e).__name__} — {e}")
        return False
    finally:
        winapi.revert_to_self()


def test_write_via_bindlink(token):
    """Write a file through the bind link under the restricted token."""
    log("TEST", "Writing through bind link under restricted token...")
    write_path = os.path.join(VIRTUAL_DIR, "write-test.txt")
    backing_path = os.path.join(BACKING_DIR, "write-test.txt")

    for p in [write_path, backing_path]:
        if os.path.exists(p):
            os.remove(p)

    winapi.impersonate_token(token)
    try:
        with open(write_path, "w") as f:
            f.write("written under restricted token")
        log("INFO", "Write through bind link succeeded.")
    except PermissionError as e:
        log("FAIL", f"Write via bind link: PermissionError — {e}")
        return False
    except Exception as e:
        log("FAIL", f"Write via bind link: {type(e).__name__} — {e}")
        return False
    finally:
        winapi.revert_to_self()

    if os.path.exists(backing_path):
        content = open(backing_path).read()
        log("PASS", f'Write test: file landed in backing dir with "{content}"')
        return True
    else:
        log("FAIL", "Write test: file not found in backing dir.")
        return False


def test_forbidden_blocked(token):
    """Confirm the restricted token CANNOT read the forbidden dir."""
    log("TEST", "Reading forbidden dir under restricted token (expect denial)...")
    winapi.impersonate_token(token)
    try:
        path = os.path.join(FORBIDDEN_DIR, "secret.txt")
        content = open(path).read()
        log("FAIL", f'Forbidden read SUCCEEDED (should have been denied): "{content}"')
        return False
    except PermissionError:
        log("PASS", "Forbidden read correctly denied (PermissionError).")
        return True
    except Exception as e:
        log("FAIL", f"Forbidden read: unexpected error — {type(e).__name__}: {e}")
        return False
    finally:
        winapi.revert_to_self()


def cleanup(synthetic_sid=None, users_sid=None, token=None):
    log("STEP", "Cleaning up...")
    winapi.remove_bind_link(VIRTUAL_DIR)
    if token:
        winapi.close_handle(token)
    if synthetic_sid:
        winapi.free_sid(synthetic_sid)
    if users_sid:
        winapi.free_sid(users_sid)
    if os.path.isdir(TEST_ROOT):
        shutil.rmtree(TEST_ROOT, ignore_errors=True)
    log("OK", "Cleanup done.")


def main():
    synthetic_sid = users_sid = token = None
    results = []
    try:
        synthetic_sid, users_sid, token = setup()
        results.append(("Read through bind link (restricted token)", test_read_via_bindlink(token)))
        results.append(("Write through bind link (restricted token)", test_write_via_bindlink(token)))
        results.append(("Forbidden dir blocked (restricted token)", test_forbidden_blocked(token)))
    finally:
        cleanup(synthetic_sid, users_sid, token)

    print()
    all_pass = all(r for _, r in results)
    for name, passed in results:
        print(f"  {'PASS' if passed else 'FAIL'}  {name}")
    print()
    print(f"PoC 2 overall: {'PASS' if all_pass else 'FAIL'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
