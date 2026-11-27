# P0-03 hosted font-intake wrapper correction

GitHub run 45869526959 failed before downloading fonts because the host wrapper
precreated the evidence directory that the bounded inspector exclusively creates.
The correction keeps the live systemd log in a separate fresh file, validates
both pipeline statuses, then moves the regular log into a direct evidence
directory after the inspector exits.

- `before.log` retains the expected regression failure against the old wrapper.
- `after.log` retains 12 passing focused font integration/intake tests.
- `repository-check.log` retains 278 passing image tests and the complete serial
  Rust, Cedar and supply-chain gate.
- `45870354806/` retains and independently reconciles the corrected hosted
  intake's four-file evidence artifact. Metadata for its separate candidate
  payload is retained without downloading that payload locally.
- `record.json` binds the failure, correction and successful hosted consumers.

Corrected [run 45870354806](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45870354806)
passed at `d436c6e`: three exact assets were authenticated and 103 members,
including 98 fonts, were passively inventoried. The intake extracted no archive
and invoked no font parser. It recorded zero OOM/kill events and zero swap.
The separate 9,647,668-byte candidate artifact remains hosted and unselected.

Consuming generic image
[run 45870354828](https://github.com/ThirdKeyAI/symbi-os/actions/runs/45870354828)
also passed. Its installed-image probe natively parsed all 98 fonts and selected
JetBrainsMono Nerd Font as the monospace default. No font input changed, and
release selection, security qualification and OS qualification remain false.
