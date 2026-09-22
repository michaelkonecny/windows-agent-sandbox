"""One-time VM provisioning for the system tests. Run elevated.

Sets ConsentPromptBehaviorAdmin=0 (admins elevate without a prompt) so the
suite runs unattended. Leaves EnableLUA=1 — the admin keeps a split token,
so `sbx start` still runs unprivileged. The suite never changes UAC itself.
"""
import ctypes
import sys
import winreg

KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"


def main() -> int:
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("run this elevated", file=sys.stderr)
        return 1
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, KEY, 0, winreg.KEY_ALL_ACCESS) as k:
        winreg.SetValueEx(k, "ConsentPromptBehaviorAdmin", 0, winreg.REG_DWORD, 0)
        lua = winreg.QueryValueEx(k, "EnableLUA")[0]
    print("ConsentPromptBehaviorAdmin = 0")
    if lua != 1:
        print("EnableLUA is not 1 — set it to 1 and reboot; the suite needs UAC on", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
