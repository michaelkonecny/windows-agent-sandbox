# Sandbox

A sandbox for safe agentic development.

- Console/terminal application.
    - fullscreen TUI

- possibility to define multiple sandboxes
For each sandbox, I should be able to define:
  - which folders are mounted where inside the sandbox?
    - perhaps also which files are mounted?
  - what is the firewall settings
    options (multiple choice, list to be extended later):
        - claude code API
        - all internet

- multiple sandboxes must be able to run at the same time.

Where to get inspiration for the technical principles:
  - idea_sandbox in ../IdeaStatiCa/ideastatica-claude\
  - anthropics sandbox: https://github.com/anthropics/sandbox-runtime
  - medium article: https://jonny-johnson.medium.com/a-deep-dive-into-codex-windows-sandbox-a2489bf4ae91
  - Florian Mücke's sandbox: https://github.com/fmuecke/claude-win-sandbox

Ideas:
  - it might be nice to be able to define the above settings in a json config, similar to devcontainers.

Notes:
  - firewall - hybrid WFP + proxy
  - 