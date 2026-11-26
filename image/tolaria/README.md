# Tolaria managed desktop integration

Tolaria is the selected default second-brain application. It stores Markdown
notes with YAML frontmatter in ordinary Git repositories, so the human can review,
commit, revert and back up every change with normal Git tools. No vault is created
silently. The human chooses an existing repository or creates one on first launch.

## Current state

The stable `v2026-11-18` source commit and pnpm 10.34.9 archive are pinned in
`source.json`. `inputs.py` passively inventories both archives, rejects links,
special files, traversal, duplicates and changed required files, and binds the
exact downstream patch. The tag is unsigned and GitHub exposed no attestation for
the source commit; those facts are recorded explicitly. This candidate is not
selected, security-qualified or OS-qualified.

The downstream patch is deliberately fail closed:

- image updates are the only application update route;
- no writable loopback MCP/WebSocket bridge starts automatically;
- durable register/remove/snippet operations cannot edit real agent configs;
- no agent is launched directly from the app;
- direct model-provider/API-key routes are disabled;
- Pi's runtime npm adapter injection is removed.
- no fixed home-directory vault is migrated or seeded before human selection.

The human editor, local vault and Git features remain. The bundled MCP server is
retained as reviewed source material for P1-13, but the desktop app does not start
or expose it. P1-13 will present smaller named contracts through the governed
runtime, with read-only access by default and writes on an isolated Git
branch/worktree. The service cannot merge or push.

## Build sequence

1. Run the bounded source-intake workflow. It downloads exact public bytes,
   performs passive inventory and deletes the private downloads without executing
   or extracting the candidate.
2. Run the separate Fedora package discovery profile. It authenticates the
   selected secureblue base and Fedora RPMs but installs nothing.
3. Review and pin that RPM artifact. Prepare an isolated compiler image; fetch
   only dependencies named by the unchanged pnpm and Cargo lockfiles.
4. Build and test with no network, one Cargo job, at most two CPUs, 6 GiB memory
   and no swap. Produce a source-bound payload and retain its manifest.
5. Check loader closure on the unchanged selected base, then integrate the binary,
   resources, icons, AGPL notice and `Tolaria.desktop` into both desktop variants.
6. Boot each variant and exercise Walker, Super+Shift+O, vault edit/commit and the
   negative routes listed above. Only then change `selected` and `os_qualified`.

Both new hosted workflows run on `main` or manual dispatch. Ordinary branch pushes
therefore do not create additional heavy jobs. Neither workflow has signing,
registry-write or release permission.

## Licence

Tolaria is AGPL-3.0-or-later. The final payload must install the exact upstream
`LICENSE` beside the application and expose the corresponding source and
downstream patch as required by that licence. Symbi OS remains Apache-2.0; the
application keeps its own licence.
