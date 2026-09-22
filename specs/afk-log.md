# AFK log — 2026-09-22, 8 h window

Decisions taken while you were away. Branch: `afk/hardening`.

- Work on hardening follow-ups from notes.md rather than new features — they're gaps in shipped behaviour.
- Found: the sandbox shell inherits the host's whole environment. Host env vars (possibly secrets) leak in, and TEMP/USERPROFILE/APPDATA point at the host profile, which the sandbox can't write — tools needing a temp dir or home break. Fix: shell env = sbx-user's own environment block (`CreateEnvironmentBlock`) + `HTTPS_PROXY`; runner gets the sbx package path and proxy port on its command line, not via env. New system test 98.
- Not pursued, for your review: the runner runs with sbx-user's unrestricted token under Windows' default process/token DACLs, and sbx-user is in every sandbox's RestrictedSids. Whether that lets a sandbox reach its runner needs a proper security review; I didn't build tooling to probe it. Candidate mitigation: the runner sets explicit DACLs on its own process, threads and token at startup (SYSTEM + host user only).
- Job Object and engine-runner pipes: replaced NULL DACLs with explicit ones (host user + SYSTEM; pipes also sbx-user read/write), single-instance pipes with a random name suffix. Covered by existing tests (stop, status, proxy lookups, session I/O); no in-sandbox probe written for it.
