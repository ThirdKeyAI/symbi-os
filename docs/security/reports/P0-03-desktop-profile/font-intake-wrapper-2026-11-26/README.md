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
- `record.json` states the hosted failure, corrected lifecycle and remaining
  native rerun requirement.

No font input or qualification state changes. The hosted rerun remains pending.
