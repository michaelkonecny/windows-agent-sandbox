"""PoC 1 — Bindlink cross-user behaviour.

Validates: a bind link created by an admin is visible and functional
for a different (sandbox) user account.

Steps:
  1. Create a local user sbx-poc-user.
  2. Create a backing directory with a test file.
  3. Log in as the user once (creates their profile).
  4. Create a virtual-path directory under the user's profile.
  5. Create a bind link: virtual path -> backing path.
  6. As sbx-poc-user, read through the bind link.
  7. As sbx-poc-user, write through the bind link.
  8. Verify the write landed in the backing directory.

Must be run elevated (admin).
"""

import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
import winapi

USERNAME = "sbx-poc-user"
PASSWORD = "P0c_Te$t!99xQ"

BACKING_DIR = r"C:\sbx-poc1-test\backing"
SCRATCH_DIR = r"C:\sbx-poc1-test"
PROFILE_DIR = rf"C:\Users\{USERNAME}"
VIRTUAL_DIR = rf"C:\Users\{USERNAME}\poc-mount"

READ_OUTPUT = rf"{SCRATCH_DIR}\read_output.txt"
WRITE_FILE = "write-test.txt"


def log(tag, msg):
    print(f"[{tag:5s}] {msg}")


def setup():
    if not winapi.is_elevated():
        sys.exit("ERROR: must run elevated (admin).")

    # Clean leftovers from a previous failed run
    winapi.remove_bind_link(VIRTUAL_DIR)

    log("STEP", "Creating local user...")
    created = winapi.create_user(USERNAME, PASSWORD)
    log("OK", f"User {USERNAME} {'created' if created else 'already existed'}.")

    log("STEP", "Creating backing directory with test file...")
    os.makedirs(BACKING_DIR, exist_ok=True)
    with open(os.path.join(BACKING_DIR, "test.txt"), "w") as f:
        f.write("hello from backing")

    log("STEP", f"Granting {USERNAME} full control on scratch dir...")
    winapi.grant_access(SCRATCH_DIR, USERNAME, "(OI)(CI)F")
    winapi.grant_access(BACKING_DIR, USERNAME, "(OI)(CI)F")

    log("STEP", "Triggering profile creation (first logon)...")
    winapi.run_as_user(USERNAME, PASSWORD, "cmd.exe /c echo profile-created")
    time.sleep(1)
    if not os.path.isdir(PROFILE_DIR):
        sys.exit(f"ERROR: profile dir {PROFILE_DIR} was not created.")
    log("OK", f"Profile directory exists: {PROFILE_DIR}")

    log("STEP", "Creating virtual-path directory...")
    os.makedirs(VIRTUAL_DIR, exist_ok=True)

    log("STEP", "Creating bind link...")
    winapi.create_bind_link(VIRTUAL_DIR, BACKING_DIR)
    log("OK", f"Bind link: {VIRTUAL_DIR}  ->  {BACKING_DIR}")


def test_read():
    """Read test.txt through the bind link as the sandbox user."""
    log("TEST", "Reading through bind link as sandbox user...")
    for f in [READ_OUTPUT]:
        if os.path.exists(f):
            os.remove(f)

    cmd = f'cmd.exe /c type "{VIRTUAL_DIR}\\test.txt" > "{READ_OUTPUT}" 2>&1'
    exit_code = winapi.run_as_user(USERNAME, PASSWORD, cmd)

    if exit_code != 0:
        log("FAIL", f"Read command exited {exit_code}.")
        if os.path.exists(READ_OUTPUT):
            log("INFO", open(READ_OUTPUT).read())
        return False

    content = open(READ_OUTPUT).read().strip()
    if content == "hello from backing":
        log("PASS", f'Read test: got "{content}"')
        return True
    else:
        log("FAIL", f'Read test: expected "hello from backing", got "{content}"')
        return False


def test_write():
    """Write a file through the bind link as the sandbox user, verify in backing dir."""
    log("TEST", "Writing through bind link as sandbox user...")
    write_via_link = rf"{VIRTUAL_DIR}\{WRITE_FILE}"
    write_in_backing = os.path.join(BACKING_DIR, WRITE_FILE)

    if os.path.exists(write_in_backing):
        os.remove(write_in_backing)

    cmd = f'cmd.exe /c echo written-by-sandbox> "{write_via_link}" 2>&1'
    exit_code = winapi.run_as_user(USERNAME, PASSWORD, cmd)

    if exit_code != 0:
        log("FAIL", f"Write command exited {exit_code}.")
        return False

    if not os.path.exists(write_in_backing):
        log("FAIL", f"Written file not found at backing path: {write_in_backing}")
        return False

    content = open(write_in_backing).read().strip()
    log("PASS", f'Write test: file appeared in backing dir with content "{content}"')
    return True


def cleanup():
    log("STEP", "Cleaning up...")
    winapi.remove_bind_link(VIRTUAL_DIR)
    winapi.delete_user(USERNAME)
    if os.path.isdir(SCRATCH_DIR):
        shutil.rmtree(SCRATCH_DIR, ignore_errors=True)
    if os.path.isdir(VIRTUAL_DIR):
        shutil.rmtree(VIRTUAL_DIR, ignore_errors=True)
    log("OK", "Cleanup done.")


def main():
    results = []
    try:
        setup()
        results.append(("Read through bind link (cross-user)", test_read()))
        results.append(("Write through bind link (cross-user)", test_write()))
    finally:
        cleanup()

    print()
    all_pass = all(r for _, r in results)
    for name, passed in results:
        print(f"  {'PASS' if passed else 'FAIL'}  {name}")
    print()
    print(f"PoC 1 overall: {'PASS' if all_pass else 'FAIL'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
