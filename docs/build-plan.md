# Symbiont OS — Build Plan for Coding Agents

Nov 24, 2026 · @Jascha

## How to use this plan

Symbiont OS is a desktop Linux system where AI agents work as visible, least-privileged principals and only the human can grant authority. It ships as a signed Fedora Atomic image with Hyprland on top and the Symbiont runtime as its enforcement core. This document is the build plan, written so coding agents (Claude Code, Codex, Pi, Cursor) can pick up work without further context.

**Rules for agents working from this plan**

1. Read *Architecture overview* and *Security invariants* before touching any code. Every change must keep every invariant.
2. Take work only from a task card in *Agent handoff protocol*. One card per branch and PR.
3. Every PR names the invariant IDs it touches (for example `INV-3`) and the tests that prove them.
4. Never weaken an invariant, a pin, a signature check or a sandbox boundary to make a test pass. Stop and open a question instead.
5. Unknowns become entries in *Risks and open questions*, not guesses in code.
6. Trusted-core components (marked **TCB**) need a TLA+ model and a human review before merge.

**Glossary**

| Term | Meaning |
| --- | --- |
| Principal | Anything that can act: the human, an agent, a harness (Claude Code, Codex, Pi, Cursor), the voice assistant |
| Grant | A scoped, time-limited Cedar permit created by a human action (drag, pick, approve) |
| Gate | Symbiont's Cedar policy check; fails closed |
| ORGA | Observe, Reason, Gate, Act: Symbiont's reasoning loop |
| ToolClad contract | Declarative `.clad.toml` describing one tool call an agent may make |
| Service manifest | Signed file registering a service's human face and agent faces |
| Session class | Data-sensitivity label on an agent session, set at grant time (for example `client-confidential`) |
| Trusted path | Compositor-drawn approval surface that accepts only physical input |
| Journal | Symbiont's hash-chained, Ed25519-signed audit log |
| TCB | Trusted computing base: code whose bugs break the security model |

## Architecture overview

Authority flows one way: from the human's physical input, through trustd, into grants that the Symbiont gate enforces. Agents never hold authority, and every exit from a sandbox goes through a broker that asks the gate.

&#91;embedded content: architecture · trusted core, agents, brokers\]

Solid arrows carry grants and traffic; the dashed arrow means UI apps can only ask trustd, never grant.

- **Trusted core (TCB):** symbi-trustd, the grant broker, the Symbiont gate, symbi-egressd and symbi-modeld. Each gets a TLA+ model and human review.
- **Not trusted:** UI apps, the service and browser brokers, and every agent. They can request or narrow authority; only the gate decides.
- **Platform:** a signed Fedora Atomic image, a patched Hyprland that owns the trusted path, and Linux isolation (Landlock, network namespaces, cgroups, SELinux), with gVisor or Firecracker for untrusted agents.

## Building on Symbiont 3.0

Most of the trusted core already exists in [Symbiont](https://github.com/thirdkeyai/symbiont) 3.0.0 (Apache-2.0; analysed at commit `deddb9e`, 23 Nov 2026). This OS adds the desktop trusted path, grants made by human designation, packaging and the desktop UI, and extends the runtime only where the right-hand column says so.

| Plan component | Already in Symbiont 3.0 | What this plan adds |
| --- | --- | --- |
| symbi-run | [Managed CLI route](https://github.com/thirdkeyai/symbiont/blob/main/docs/managed-cli-containment.md) (`executor = "claude_code"`): Claude Code runs in a Landlock, Docker, gVisor or Firecracker worker with built-in tools, plugins and discovery off; source access only through ToolClad tools via the prepared-call dispatcher; provider credentials stay in the runtime. `symbi init --sandbox landlock --profile dev-agent` scaffolds it. Headless CLI adapters for Codex and Aider exist | Desktop launcher; Codex and Pi on the governed route; workspace mode |
| Worker isolation | Landlock ABI 6 workers under a delegated systemd user supervisor (cgroup v2 limits, private tmpfs, loopback-only network namespace); independent sandbox supervisor; shared worker capacity | Qualification on the Fedora Atomic image |
| symbi-modeld | Managed inference broker (fixed Messages routes, model checks, output-token reservations, credential-reflection checks); OpenAI, Anthropic and OpenRouter clients; SLM-first routing module; llama.cpp `LocalGgufRunner`; shared token budgets per run family | Standalone OS gateway; Chat Completions and Responses fronts; session-class routing; per-day spend quotas; GPU scheduling |
| symbi-egressd | [Outbound capabilities](https://github.com/thirdkeyai/symbiont/blob/main/docs/outbound-capabilities.md): named HTTP operations per ToolClad tool, credentials from Vault/OpenBao or an encrypted file store injected by the runtime, SSRF checks, per-run revocable authority, signed effect records | Allowlisted CONNECT proxy for workspace mode only |
| Grant broker | Source and output root ceilings; [per-operation file grants](https://github.com/thirdkeyai/symbiont/blob/main/docs/filesystem-grants.md) (read-only input snapshots, one new output published after cleanup) | Turning picks and drags into those grants |
| symbi-trustd | Shared escalation queue issuing exact, single-use receipts bound to the prepared call; terminal relay requiring the foreground TTY; escaped request rendering | Compositor-drawn, physical-input-only surface; other approval surfaces locked out |
| Journal | Required protected per-run journals (hash chain, Ed25519, synced before effect); `symbi audit inspect`; `ProtectedJournal::verify` | Trace monitor against the TLA+ models |
| Flight Recorder, Control Center | A2UI console (Lit/TypeScript) with Run Inspector, audit trail, worker capacity, fleet overview, tools and compliance panels; runtime HTTP and WebSocket API | Desktop shell, live timeline, approvals handed to trustd |
| Skills and Store | SKILL.md loader; `symbi-skill-v2` signatures (SchemaPin over every file digest); ClawHavoc scanner (40 rules); `symbi skills list`, `scan`, `verify` | Capability manifests (`skill.toml`); the Store |
| Policy studio | `symbi policy evaluate`; `symbi tools validate` and `test` dry runs; `repl-lsp` | Z3 property checks; UI |
| symbi doctor | `symbi doctor` checks the boundary, supervised launch, namespaces and managed CLI startup | Image signature, bootc and trustd checks |
| Evidence | `docs/security/controls.json` control catalogue with qualification reports | The 14 invariants registered as controls |
| Voice | Slack, Teams and Mattermost channel adapters; coordinator delegation through `CommunicationPolicyGate`; `symbi-invis-strip` | A voice channel adapter |

**Rules for agents touching Symbiont**

- Pin Symbiont by commit. Runtime changes go upstream first and follow its `AGENTS.md` and evidence conventions.
- Rely only on routes Symbiont documents as supported for the chosen backend. Its own docs state that full containment across all entry points is not established, that browser execution is unavailable, and that the Landlock route does not yet serve PTYs or registered HTTP and scheduled agents.
- A new security property needs a `controls.json` entry and a retained qualification report, not only tests.

## Security invariants

These 14 rules define the product; a build that breaks one is not shippable. Each TCB rule gets a TLA+ model (via `skill-formal-proofs`), fault checks that prove the model catches a broken implementation, and trace-conformance checks against the journal.

| ID | Invariant | Enforced by | Proof |
| --- | --- | --- | --- |
| INV-1 | **Complete mediation.** No agent side effect (file, network, exec, IPC to a service) happens without a Gate decision. Model output is never authority. | Symbiont gate, sandbox, egressd | TLA+ + trace check |
| INV-2 | **Only the human grants.** Grants are created, widened or extended only by a trusted-path confirmation or a designation act (drag, pick) made with physical input. No agent, UI app or voice command can grant. | trustd, grant broker | TLA+ |
| INV-3 | **Revocation is final.** After a revoke is acknowledged, no action under that grant completes. In-flight calls are cancelled or finish before the ack. | gate, egressd, modeld | TLA+ (race model) |
| INV-4 | **Physical input only.** Synthetic input (uinput, virtual-keyboard protocol, agent input, voice) never reaches a trusted-path surface. | trustd + compositor protocol | TLA+ + fuzz |
| INV-5 | **Journal before effect.** Each executed action is journaled (hash-chained, signed) before its effect is released. | Symbiont journal, egressd | TLA+ + crash tests |
| INV-6 | **No secrets in sandboxes.** Provider keys and OAuth tokens stay in Vault/OpenBao and are injected at egress. | egressd, modeld | Tests + audit |
| INV-7 | **One way out.** An agent's network namespace reaches only egressd and modeld sockets. | symbi-run, netns | Tests |
| INV-8 | **Session-class confinement.** A session classed `client-confidential` never sends content to a remote model, voice service or API. | modeld, egressd, voice | TLA+ + tests |
| INV-9 | **Transport-independent decisions.** API, agent browser and shared tab routes for one request get the same Cedar decision. | service broker | TLA+ |
| INV-10 | **Stop-the-world.** After a freeze is acknowledged, no agent action completes until resume. | trustd, cgroup freezer | TLA+ |
| INV-11 | **Skills only narrow.** Effective authority = agent grants ∩ skill manifest. | gate | Tests + Z3 |
| INV-12 | **Pinned and signed.** Images, contracts, manifests, skills, model weights and wake-word models are pinned by hash and signature-checked before use. | image pipeline, store, modeld, voice | Tests |
| INV-13 | **Project config only narrows.** A repo's local config cannot change providers, routing, sandbox or egress. | symbi-run, modeld | Tests |
| INV-14 | **Voice is never authority.** Voice cannot approve or grant. Audio stays on-device until a wake event and a policy decision allow it out. | voice service, trustd | TLA+ + tests |

Register each invariant as a control in Symbiont's catalogue (`docs/security/controls.json`) with retained qualification reports; a passing test alone is not a validation claim.

## Base OS and image pipeline

The product image is Fedora Atomic (bootc), built with [BlueBuild](https://blue-build.org) on top of [secureblue](https://github.com/secureblue/secureblue)'s `wayblue-hyprland-main-userns-hardened` image, plus an `-nvidia` variant. Everything is built and tested on this image from day one, including Phase 1. Useful [Ombuntu](https://ombuntu.org) pieces are ported to it instead of running on Ubuntu (see the porting table below).

**Implementation finding (25 Nov 2026):** upstream has retired the named Hyprland family and separate userns variants. The original choice below is not a usable current pin. See [OQ-07](open-questions.md) and [the image preparation record](../image/README.md); selecting a replacement must preserve the trusted-compositor requirements.

**Why this base:** current kernel and Hyprland, SELinux, signed images with atomic rollback, and hardening already done. Debian stable ships Hyprland 0.41.2 against 0.57.x upstream, so it would mean maintaining Hyprland packaging ourselves. The `userns` variant is required because the Claude Code and Codex sandboxes use bubblewrap.

**Image contents**

- Symbiont runtime and the `symbi-*` services from this plan, as systemd units with SELinux policy modules.
- Hyprland, Waybar and Walker configs adapted from Omarchy, plus an Agents section in the single Super + Alt + Space menu.
- Owner-selected desktop profile: MPlayer, Ombuntu-style menus, Tokyo Night as the initial theme, Kitty as the default terminal, Nerd Fonts and the inspected local terminal customizations. Preserve the owner's existing keyboard shortcuts, including local overrides; the application launcher stays on Super + Space and the main menu on Super + Alt + Space. Exact requirements, local observations and the full shortcut reference are in [Desktop defaults and Ombuntu compatibility](desktop-profile.md). These additions remain pending in P0-03.
- Managed browser policies (telemetry off, keyring-backed passwords) and developer-tool telemetry opt-outs, borrowed from Ombuntu.
- Security by removal: `hyprpm` and all Hyprland plugins disabled, no menu extensions, no remote themes, no `curl | sh` installers anywhere.

**Porting Ombuntu to Fedora Atomic**

| Ombuntu piece | Fedora Atomic equivalent |
| --- | --- |
| Omarchy pinned at a tag, overlay copied on top | Same pattern at image build time: Omarchy configs pinned by commit, our overlay applied in the BlueBuild recipe. Defaults live in `/usr/share/symbiont/defaults` and are copied to `~/.config` on first login without overwriting existing files |
| apt packages and vendor apt repos | Packages layered in the image recipe from Fedora repos; RPM repo GPG keys pinned in the image with `gpgcheck=1`; no `rpm-ostree install` on the user's machine |
| Pinned, checksummed GitHub downloads (Walker, Elephant, fonts, mise) | Same downloads with sha256 checks, done only at image build time; nothing fetched on the user's machine |
| Signed release tags and `ombuntu update` | cosign-signed images; `bootc upgrade` to the signed image, rollback via bootc |
| `uninstall.sh` | Rebase back to the plain secureblue image |
| Install menu (apt, snap, vendor repos) | Flathub apps, plus toolbox/distrobox containers for CLI tools; no `curl \| sh`, no snap, no AUR |
| Crash reporting and Ubuntu telemetry off | Remove or disable ABRT and any Fedora telemetry present in the base; Ubuntu Pro items dropped |
| NetworkManager connectivity probe off | Same drop-in under `/etc/NetworkManager/conf.d/` |
| Firefox and Chromium-family managed policies | Same policy files at the Fedora package paths, shipped in the image |
| Keyring-backed browsers and dev-tool telemetry opt-outs | Same libsecret launch flags and `/etc/profile.d` variables, shipped in the image |
| No passwordless sudo, no autologin, screen share asks every time | Same settings; the portal's no-restore-token setting ships in the image |
| `ombuntu-doctor` | `symbi doctor`, plus image signature, bootc and sandbox checks |
| `agent-guide.md` | `os-agent-guide`, generated from the installed contracts |

**Pipeline**

1. The recipe pins the base image by digest, not by tag.
2. CI builds the image, generates an SBOM and a SLSA provenance attestation, and signs with cosign using ThirdKey keys.
3. Users install with `rpm-ostree rebase ostree-image-signed:docker://ghcr.io/<org>/symbiont-os:<tag>`; unsigned images are refused.
4. A scheduled `upstream-check` job (the Ombuntu idea) rebuilds against a newer base digest, runs the full test suite and opens a bump PR only when everything passes.
5. Fedora releases roughly every six months; each rebase is a tracked task card.

**Later hardening (Phase 5):** unified kernel images, dm-verity and TPM-measured boot following [ParticleOS](https://github.com/systemd/particleos), so a user can build and sign the image with their own keys.

**Acceptance criteria**

- [ ] `bootc status` shows a signed image; rebasing to an unsigned image fails.
- [ ] Plugin loading is blocked even if a user drops a `.so` in the plugin path.
- [ ] SBOM and provenance attestation are published for every release tag.
- [ ] Rollback to the previous deployment boots and passes the smoke suite.

## Phase 1: symbi-run, symbi-egressd, symbi-modeld

Phase 1 puts coding agents under Symbiont's managed CLI route on the Fedora Atomic image, adds a workspace mode for everyday coding, and turns Symbiont's inference broker into an OS-wide model gateway. Everything is built and tested on the image from day one.

### symbi-run (harness launcher)

`symbi-run <harness> [--mode governed|workspace] [--project DIR] [--class public|internal|client-confidential] [--model ALIAS] [--tier landlock|gvisor|firecracker] -- <harness args>`

A thin desktop launcher: it generates a Symbiont control project per principal (kept outside the source repository, as Symbiont requires) and calls `symbi run`. It has two modes.

- **Governed mode (default).** Symbiont's managed CLI route as shipped. The harness's built-in tools, plugins and project discovery are off; it sees private scratch space and reaches source only through registered ToolClad tools (`read_file`, `list_files`, `grep_files`, Git queries). Every call is prepared, approved if required, checked by Cedar, journaled, then dispatched. Writes need declared outputs or an exact approval. Use it for review, research and untrusted repositories.
- **Workspace mode (new).** For everyday coding the harness keeps its own edit and shell tools, but runs in a Landlock worker against a private writable snapshot of the project. Its network reaches only symbi-modeld and, if granted, package registries through egressd. At the end of the task symbi-run produces a diff, takes a btrfs snapshot of the real repository, and applies the diff only after the human approves it (Symbiont's terminal relay until trustd exists). The `symbi-claude-code` hooks run inside for per-tool Cedar checks and visibility; they are advisory, and the sandbox is the boundary.

| Harness | Governed mode | Workspace mode | Work needed |
| --- | --- | --- | --- |
| Claude Code | Shipping in Symbiont; tested upstream with Claude Code 2.1.274 | Yes, with `symbi-claude-code` hooks | Desktop profile; workspace mode |
| Codex | Not yet: Symbiont's Codex adapter is headless only, and the governed route and inference broker are Claude/Messages only | Yes | Responses and Chat routes in the inference broker; MCP tool-bridge config; governed adapter |
| Pi | No adapter | Yes | New adapter; confirm Pi can use the MCP tool bridge (open question) |
| Cursor | Not possible: its requests go through Cursor's backend, so inference cannot be brokered | Remote-only, with the `symbi-claude-code` Cursor `preToolUse` hooks; egress only to Cursor hosts | Profile only; refused in confidential sessions |

- **Credentials.** Governed mode keeps provider keys in the runtime and gives the child a placeholder, as Symbiont does today. Subscription logins (Claude Pro/Max, ChatGPT plans) work only in workspace mode, where the harness's own token sits in its per-principal `HOME` and egress is limited to that vendor's hosts. This is a documented exception to INV-6, marked in the UI; check each vendor's terms first (open question).
- **Project config only narrows** (INV-13). Symbiont already refuses to expose control paths through source mounts.

### symbi-egressd

- **Service APIs:** use Symbiont's outbound capabilities unchanged: named operations per ToolClad HTTP tool, credentials injected by the runtime from Vault/OpenBao or an encrypted file store, SSRF and path checks, per-run revocable authority, signed effect records.
- **New, workspace mode only:** a small allowlisted CONNECT proxy for package registries and vendor hosts. One listener per principal on a Unix socket; it journals host, bytes and decision, and closes connections on revoke (INV-3) or freeze (INV-10).
- Governed workers keep no network beyond Symbiont's private tool and inference channels.

### symbi-modeld (model gateway)

- **Start from Symbiont's managed inference broker** (fixed routes, model checks, output-token reservations, credential-reflection checks, buffered streams) and its provider clients for OpenAI, Anthropic, OpenRouter and any OpenAI-compatible endpoint such as Ollama.
- **Add:** a standalone OS service; Chat Completions and Responses fronts beside Messages, so Codex and Pi can be brokered; session-class routing in the Cedar context (INV-8); virtual keys per principal; per-day spend quotas, because Symbiont's budgets cover one run family, not an account.
- **Policy:** action `model.invoke` on a `Model` resource with attributes `location`, `provider`, `jurisdiction`, `cost`. Example: `forbid(principal, action == Action::"model.invoke", resource) when { resource.location == "remote" && context.session_class == "client-confidential" };`
- **Local models:** Symbiont's `LocalGgufRunner` (llama.cpp) and SLM-first routing module for small utility models; vLLM and Ollama as OpenAI-compatible backends. Weights GGUF or safetensors only, pinned by sha256 (INV-12).
- **GPU scheduler:** one queue (interactive, then voice, then background) with load and unload inside a VRAM budget; agents never get GPU devices.
- **No LiteLLM:** this keeps Python out of the trusted core.
- **Registry:** `/etc/symbi/models.toml` (system), `~/.config/symbi/models.toml` (user; a new remote provider needs trusted-path confirmation); project files only narrow.
- Every call lands in the run's protected journal, and a D-Bus signal on each remote call drives the egress light.

### Acceptance criteria

- [ ] Symbiont's Landlock platform diagnostic and release driver pass on the Fedora Atomic image, with the report retained (P0-04).
- [ ] Claude Code completes a review in governed mode and a coding task in workspace mode, with the user's real config untouched.
- [ ] In workspace mode, nothing reaches the real repository until the diff is approved.
- [ ] From inside any worker, connections to hosts off the allowlist fail, including direct provider access.
- [ ] In governed mode, no provider key appears in the worker's environment, files or memory.
- [ ] A `client-confidential` session asking for a remote model is denied and journaled; the same request to a local model succeeds.
- [ ] Revoking a principal ends an in-flight model response within 1 second.
- [ ] A malicious project config cannot change routing.
- [ ] Cursor refuses to start in a confidential session.

## Phase 2: symbi-trustd and the grant broker

Phase 2 makes the human the only source of authority: a trusted approval surface that agents cannot draw over, fake or click, and a broker that turns ordinary file picks and drags into scoped grants. Write the TLA+ models (`GrantLifecycle.tla`, `TrustedInput.tla`, `Freeze.tla`) before the code.

**Built on Symbiont.** trustd is a new surface for Symbiont's shared escalation queue, which already issues exact, single-use receipts bound to the prepared call, principal and session; reuse its request rendering, which escapes control and non-ASCII characters. Other surfaces must not be able to resolve desktop approvals: on the desktop profile, the runtime's HTTP `/api/v1/approvals/{id}/approve` and `/deny` routes and chat-channel approvals are turned off or require a trustd receipt (card P2-06). The grant broker writes Symbiont's existing source and output root ceilings and per-operation file grants rather than a new format.

### symbi-trustd (TCB)

- **Compositor protocol, not a plugin.** A small Wayland extension `symbi_trusted_surface_v1`, carried as a patch in our Hyprland build. Only a process with trustd's SELinux context can bind it. Its surfaces sit on a layer above everything and are excluded from screen capture by agent principals.
- **Input provenance.** The compositor tags every input event as physical (libinput devices) or synthetic (uinput, `virtual-keyboard`, `virtual-pointer`). Trusted surfaces accept physical input only (INV-4).
- **Agent input.** Agents get no `/dev/uinput` (SELinux + device cgroup) and no raw virtual-input protocols. They type and click only through a mediated `symbi_agent_input_v1`, which tags the principal and draws a ghost cursor in the agent's colour.
- **Secure attention key.** A configurable chord the compositor intercepts before any client. It always opens the trustd overview: pending approvals, active grants and the freeze button.
- **Approval cards** show the principal (AgentPin identity and colour), the ToolClad contract with concrete arguments, the session class, and the agent's stated reason clearly marked as untrusted text. Choices: Once, Always for this scope (with an expiry), Deny. Buttons arm only after the card has been visible for 500 ms and the pointer has moved inside it, to block click-jacking.
- **Stop-the-world.** One chord freezes every agent cgroup (`cgroup.freeze`), pauses egressd and modeld, and journals the event; only trustd can resume (INV-10).
- **Credential entry.** OAuth flows and API-key entry happen only in trustd surfaces; secrets go straight to Vault/OpenBao.
- **Fallback** if the Hyprland patch proves unmaintainable: trusted surfaces on a dedicated minimal compositor session switched to by the secure attention key.

### Grant broker (powerbox)

- **Portal backend.** An xdg-desktop-portal backend implementing FileChooser, OpenURI, Screenshot and ScreenCast for agent principals. A file the human picks becomes a grant on that path for the requesting principal; nothing else is reachable.
- **Drag and drop.** A drag from the human's file manager or browser onto an agent's window or bar icon is a designation act made with physical input, so it creates a grant (INV-2).
- **Grant format.** One Cedar file per grant under `/var/lib/symbi/grants/<principal>/<id>.cedar`, with expiry, scope and the journal hash of the human act that created it.
- **Session class.** Paths can carry `user.symbi.class` extended attributes. Granting a labelled path raises the session's class; a class never goes down within a session.
- **Revocation.** Delete the grant, reload the gate, notify egressd and modeld, close affected connections, then acknowledge (INV-3).
- **CLI:** `symbi grants list | show | revoke`.
- **Screen and tab sharing** always asks per session and is never remembered.

### Acceptance criteria

- [ ] An agent with computer-use control cannot approve its own request by any synthetic input path (fuzzed).
- [ ] Screen capture by an agent never shows a trusted surface.
- [ ] Picking a file grants that file only; sibling files stay denied.
- [ ] Revoke, then attempt: denied in 100% of 10,000 randomized race runs.
- [ ] Freeze stops a running harness, an in-flight model stream and an open egress connection within 500 ms.
- [ ] TLA+ models pass, and their fault checks fail when a guard is removed.

## Phase 3: agent bar, Flight Recorder, Control Center

Phase 3 makes agents visible. All three apps are outside the TCB: they can narrow authority directly (revoke, freeze, lower a budget) but any request that widens it opens a trustd card (INV-2).

**Built on Symbiont.** The Flight Recorder and Control Center extend Symbiont's A2UI console (Lit/TypeScript), which already has Run Inspector, audit trail, worker capacity, fleet overview, tools and compliance panels, wrapped in a minimal webview shell. The agent bar reads the runtime's agent event and sandbox capacity APIs. Approve buttons in A2UI hand off to trustd instead of calling the runtime's approval routes.

### Agent bar and window identity

- A Waybar module backed by a small Rust helper subscribed to `land.symbiont.*` D-Bus signals.
- Per agent: colour, name, ORGA phase, sandbox tier, model badge (local or remote), budget left, and the egress light that turns on while session content is going to a remote model or service.
- **Borders come from the compositor, not the client.** The compositor maps each client's PID to its cgroup and principal and draws that principal's colour, so an agent cannot paint itself as another agent or as the human.
- Optional workspace per agent. Freeze is one click; resume always goes through trustd.

### Flight Recorder

- Reads the journal through a read-only API and verifies the hash chain and signatures on load; a broken chain shows a red banner, never a silent gap.
- Timeline per agent and per task: decisions, tool calls, egress, model calls, file changes, and screenshots of browser actions.
- Filters by principal, service, decision and session class.
- Daily summaries from the `flight-recorder-review` skill, run on a local model by default.
- Exports a signed bundle of a time range for incident review.
- Rollback buttons arrive with snapshots in Phase 5.

### Control Center

- Agents, grants, skills, services, models, budgets and settings, plus an inbox for approvals that can wait. Choosing Approve opens the trustd card; the Control Center never approves anything itself.
- Extend Symbiont's A2UI console, wrapped in a minimal webview shell; no new UI stack.
- Linked from an Agents section in the Super + Alt + Space menu.

### Acceptance criteria

- [ ] An agent cannot change its own border colour or title prefix.
- [ ] Driving the Control Center with synthetic input can revoke or freeze but never grant.
- [ ] Flight Recorder flags a single modified journal byte.
- [ ] Egress light turns on within 200 ms of a remote model call starting.

## Phase 4: service broker and browser broker

Phase 4 lets a user register a service once and get a human face (a web-app window) plus agent faces, with policy written against the service and operation rather than the transport (INV-9).

**Built on Symbiont.** The API route is Symbiont's outbound capabilities: a manifest's `contracts` become ToolClad HTTP tools bound to named capabilities, so credentials, SSRF checks, revocation and effect records come for free. ToolClad already defines `mode = "browser"` manifests with URL-scope checks, but its CDP executor is not implemented and public browser execution is unavailable; the browser broker should implement that executor upstream rather than define a second format.

### Service manifest

```toml
# /etc/symbi/services/google-maps.svc.toml  (signed)
[service]
id      = "google-maps"
origins = ["https://www.google.com/maps", "https://maps.googleapis.com"]

[human]
webapp = "https://www.google.com/maps"

[agent.api]
contracts = ["maps.geocode", "maps.directions", "maps.places_search"]  # ToolClad
auth      = "api_key"                 # held by egressd, injected at egress
budget    = { daily_cents = 500 }

[agent.browser]
modes   = ["view_user_tab", "own_profile"]
default = "read_only"
```

### Service broker

- Loads signed manifests (SchemaPin), turns `origins` into egressd allowlists and `contracts` into gate actions.
- **Routing:** an agent asks for an operation (`maps.directions(A, B)`); the broker picks the most preferred route the agent is allowed: API or MCP server, then the agent's own browser profile, then the human's tab. One Cedar action and one journal record, whatever the route.
- **Add a service:** Control Center, then Services, then Add. Pick from the signed catalog or point at an OpenAPI spec; `symbi-service-onboard` drafts contracts and a manifest, the human reviews and signs locally, and credentials are entered in a trustd surface.
- **Handoffs:** an agent's result can open in the human face (for example, directions open in the Maps window).
- Respect each service's terms: for Google Maps, the API route is the default and browser use is limited to viewing the human's own tab.

### Browser broker

- **Agent profiles:** one sandboxed Chromium profile per agent, driven over CDP/WebDriver BiDi, with navigation limited to the manifest's origins and a screenshot of every action in the journal.
- **Shared tab:** a small extension in the human's browser shares one tab read-only (accessibility tree and screenshots) after a drag onto the agent; access lasts for the session and is never remembered.
- **Acting in the human's tab** is the highest-risk route: every write action (submit, purchase, send) needs a trustd approval, and input arrives through `symbi_agent_input_v1` with a ghost cursor.

### Acceptance criteria

- [ ] The same request through API, agent profile and shared tab produces identical gate decisions (property test).
- [ ] An agent profile cannot navigate outside its manifest's origins, including via redirects.
- [ ] A form submit in the human's tab is blocked until approved on the trusted path.
- [ ] An OpenAPI spec for a public API onboards end to end in under 10 minutes of human time.

## Phase 5: skills and Store, policy studio, snapshots, trace monitor, image hardening

Phase 5 makes the system extensible without widening its trust: skills that can only narrow authority, tools for writing and proving policy, undo for agent work, and a stricter boot chain.

**Built on Symbiont.** Skills already load from `SKILL.md`, are signed in the `symbi-skill-v2` format (SchemaPin over every file digest) and are scanned by the ClawHavoc scanner (40 rules in 10 categories). `skill.toml` extends that signature with a capability manifest, and `skill-audit` wraps the scanner. The policy studio builds on `symbi policy evaluate`, `symbi tools test` and `repl-lsp`; `symbi-doctor` extends the existing `symbi doctor`; the trace monitor reads journals through `ProtectedJournal::verify`.

### Skills and the Store

- A skill is a signed bundle. `SKILL.md` is prompt content with no authority; only its ToolClad contracts execute; effective authority = agent grants ∩ skill manifest (INV-11).
- Existing skills in `~/.agents/skills/` load unchanged but run **instructions-only** until a manifest is generated by `skill-audit` and approved.
- Hooks become journal-event subscriptions; checks that were CI-only become gate rules (for example, deny `git.push` while `context.verify_stale`).
- Nothing a skill needs is fetched at run time: tools such as `tla2tools.jar` are bundled and pinned by hash (INV-12).

```toml
# skill.toml (signed; publisher identity via AgentPin)
[skill]
id = "formal-proofs/tla-check"
version = "0.5.3"

[instructions]
files = ["SKILL.md", "references/*.md"]

[[contracts]]
file = "contracts/tla-check.clad.toml"

[requires]
fs.read  = ["${workspace}/formal/**", "${workspace}/src/**"]
fs.write = ["${workspace}/formal/**", "${workspace}/VERIFY.md"]
net      = []
sandbox  = "gvisor"
artifacts = [{ name = "tla2tools.jar", sha256 = "…" }]
```

**Store:** a signed catalog of system, organization and personal skills and services; installing shows the manifest as a plain list of what it reads, writes, runs and contacts.

**Skills the OS ships:** `symbi-service-onboard`, `symbi-policy-author`, `skill-audit`, `flight-recorder-review`, `os-agent-guide` (generated from installed contracts so it cannot drift) and `symbi-doctor`.

### Review of the proposed default catalog (25 Nov 2026)

The proposed ship list is a useful later-phase catalog, not a description of
what the current development image ships. The six skills listed above remain
planned. The following additions are recommended candidates for their existing
phase dependencies; this review does not add them to P0's acceptance gates or
implement contracts, grants, service manifests or skills.

| Candidate | Assessment and required boundary | Phase dependencies |
| --- | --- | --- |
| `tla-check` | Already named in the manifest example and trace-monitor design. Bundle the pinned checker, its Java runtime and required scripts; no network, gVisor, explicit model/source read scope and declared model/report outputs. Model checking alone does not implement journal adapters or continuous trace conformance. | P5-01/P5-07 packaging; P5-05 trace integration, P0-02 models |
| `governed-review` | Strong initial use case. Name `read_file`, `list_files`, `grep_files`, `git_status`, `git_diff`, `git_staged_diff` and `git_log` exactly. No `git_*` wildcard, shell or push permission. Use the upstream bounded private Git snapshots, including an explicit metadata grant, and a separate contract for one declared new report. | P1-06 qualified harness route, P5-01/P5-07 skill bundle |
| `toolclad-author` | Complements OpenAPI onboarding with local CLI contracts. Write drafts into a declared output area; never install/sign/activate them or execute generated commands automatically. Validation and test runs require separate scoped contracts. | P4-03/P4-04 authoring UI, P5-01/P5-07 bundle |
| `grant-planner` | Instructions-only advisor that proposes exact paths, operations, destinations, duration and cost. It cannot create, widen, renew or approve grants, or choose the authoritative session class. | P5-01/P5-07; P2 trusted approval integration |
| `web-research` | Useful after a reviewed web service exists. Search, fetch and site-map operations need separate bounded contracts. A new local Rust crawler is additional implementation scope, not an existing plan deliverable; search also needs a selected provider or index. | P4-01/P4-03 service, P5-01/P5-07 bundle; P4-02 if browser execution is needed |
| `supply-chain-check` | Read-only access to reviewed registries/advisory services through the broker; scoped private cache and declared report output. Bundle the checkers. Do not run arbitrary project build scripts or create audit exemptions, change trust roots, or sign approvals. A passing scan is not a source audit. | P1-03 egress, P4 service operations, P5-01/P5-07 bundle |
| `atomic-admin` | Begin with exact read-only status/diagnostic operations on bootc, rpm-ostree and installed trust state. A future mutation needs a typed broker operation, gate decision, journal and trusted approval; approval alone must not expose a root shell or unrestricted privileged socket. | P5-07 alongside symbi-doctor; any mutation additionally needs its reviewed P2/TCB integration |

The upstream baseline for this review is Symbiont
`deddb9e997244d2289c217ad76b8fde0e9b0339b`. Its
[managed launcher](https://github.com/ThirdKeyAI/Symbiont/blob/deddb9e997244d2289c217ad76b8fde0e9b0339b/src/commands/managed_cli.rs)
rejects plugin directories, selects distinct registered tool names and disables
built-in tools/project discovery. The
[Git query implementation](https://github.com/ThirdKeyAI/Symbiont/blob/deddb9e997244d2289c217ad76b8fde0e9b0339b/crates/runtime/src/sandbox/source_git.py)
uses fixed operations; its [documented scope](https://github.com/ThirdKeyAI/Symbiont/blob/deddb9e997244d2289c217ad76b8fde0e9b0339b/docs/git-source-queries.md)
includes the bounded Git object database, excludes recursive submodule review,
and refuses several repository layouts. The review skill must expose those
limits rather than promise unrestricted repository compatibility.

The harness/profile proposal agrees with Phase 1 with one correction:
`symbi-claude-code` hooks belong to workspace mode and remain advisory. Governed
Claude uses the runtime dispatcher and loads no harness plugins. Codex and Pi
need adapters, inference routes, bridge configuration and containment tests;
broker routes alone are insufficient, and Pi bridge support is still open.
Cursor stays remote-only workspace mode and is refused for confidential
sessions. Profiles must preserve the user's real harness configuration.

Signed `web`, `github`, `gitea`, `cve-bz` and `osv` service manifests fit Phase 4. A local
web engine still makes remote requests: session-class policy, origin/redirect
and DNS/SSRF checks, credentials, byte/depth/time limits, cancellation and
journaling apply. Crawl responses are untrusted data, never instructions or
executable dependencies. Reuse upstream outbound capabilities where applicable;
do not give the engine an independent unrestricted network path. Registry
CONNECT access for workspace tools belongs to P1-03; named read-only registry
queries for a governed skill require explicit service operations instead.

The owner selected [cve.bz](https://cve.bz/cve/api) as a security-information
source. Use its public API now for dependency and advisory assessment; its
Streamable HTTP MCP endpoint is `https://cve.bz/mcp`. The planned `cve-bz`
service should expose bounded advisory lookup/feed operations, with stack checks
as a distinct data-upload operation subject to session-class and egress policy.
A lockfile or SBOM can reveal private project information; the first P0 lookup
used only the already public pinned upstream Cargo.lock. Retain advisory IDs,
affected/fixed ranges, source timestamps, query/input hashes and attribution,
and cross-check relevant publisher advisories and Fedora backports. Empty
results, missing KEV/EPSS data or a successful API request are not release
approval. The [first retained assessment](security/reports/P0-03-cve-bz/2026-11-26/README.md)
records open matches; no MCP client was installed and no service authority was
created. Signed service integration remains Phase 4 work.

The proposed `verify_stale` push rule is already a Phase 5 example, not an
implemented GitHub/Gitea gate. Freshness must come from trusted verification
evidence bound to the exact repository, content and required checks; a skill or
repository file cannot clear it. Equivalent publishing effects through Git,
API and browser routes must receive the same decision (INV-9). Passing the
freshness condition does not itself grant permission to publish.

The shared-tab extension remains planned Phase 4 infrastructure with explicit
per-session human designation. It is the proposed first-party browser extension,
not a reason to alter the user's other extensions. MCP bridge configuration is
infrastructure, not a marketplace plugin. Hyprland native loading must be
blocked in the compositor even when a `.so` is present; removing `hyprpm` is
insufficient, and the current image still needs the real negative runtime test.

Correct the proposed blanket ban on runtime downloads: INV-12 requires hashes
and signature verification before use for its named artifacts. The separate
skill rule forbids fetching a skill's executable dependencies on demand. It
does not prohibit authenticated image updates, authorized workspace package
traffic or bounded web/advisory data retrieval. None of those is a path to
replace trusted tools without the required verification. No skill may grant
authority or lower a session's class; OQ-04's trusted class source remains open.

### Policy studio

Cedar editing and tests on top of Symbiont's `repl-lsp`, plus property checks with Z3 such as "no agent reaches `payments.*` without approval". Policies ship with their tests.

### symbi-snapd (snapshots)

A btrfs snapshot of each granted writable path at task start; Flight Recorder shows the diff and offers rollback per task.

### Trace monitor

Runs `tla-check` trace conformance continuously against the journal, so the TLA+ models act as a runtime monitor. A failed trace raises a trustd alert and can freeze the offending principal.

### Image hardening

Unified kernel images, dm-verity root and TPM-measured boot following the ParticleOS model, with an option for users to build and sign the image with their own keys.

### Acceptance criteria

- [ ] A skill that requests network access its manifest omits is denied at run time.
- [ ] `skill-audit` flags a run-time download in a third-party skill.
- [ ] Rolling back a task restores every changed file and nothing else.
- [ ] A journal trace that violates a model is detected within 60 seconds.

## Optional voice assistant

Voice is an opt-in feature: a local wake-word service with custom phrases, a local-first speech pipeline, and a choice of brain (local, API key, or the user's existing subscription). Voice is a principal with its own small grants, and it can never approve or grant anything (INV-14). Ship it after Phase 2, because it depends on trustd.

**Built on Symbiont.** Implement voice as a channel adapter beside Symbiont's Slack, Teams and Mattermost adapters, so spoken requests reach the coordinator through the same governed, audited delegation path. Every transcript passes through `symbi-invis-strip` before it reaches a prompt or a journal.

### Components

- **symbi-voiced (wake service).** Runs [openWakeWord](https://github.com/dscripka/openWakeWord) on ONNX Runtime with Silero voice-activity detection and Speex noise suppression. It has no network namespace at all, holds a 2-second in-memory pre-roll buffer, and emits only wake events (phrase, score, time) on a Unix socket. Audio leaves it only after a wake event.
- **Capture.** After a wake, an earcon plays and the utterance is captured until voice activity stops (15-second cap). PipeWire echo cancellation is on, and wake detection is muted while the assistant is speaking so it cannot wake itself.
- **Speech-to-text:** local whisper.cpp by default, scheduled in modeld's voice queue; a remote speech-to-text service only if policy and session class allow.
- **Brain:** the `voice` principal, routed through modeld like any agent.
- **Text-to-speech:** local [Piper](https://github.com/OHF-Voice/piper1-gpl) by default, run as a separate process; provider voices when the chosen mode supplies them.
- **Mic indicator** in the agent bar with four states: off, listening for wake word (on-device only), capturing, streaming to a remote service. One hotkey hard-disables the microphone pipeline.

### Provider modes

| Mode | How it works | Needs | Works in confidential sessions | Notes |
| --- | --- | --- | --- | --- |
| Local (default) | whisper.cpp, then a local model via modeld, then Piper | A GPU or a fast CPU | Yes | Fully offline |
| API key | OpenAI: the [Realtime API](https://developers.openai.com/api/docs/guides/realtime-conversations) speech-to-speech over a server-side WebSocket from modeld, key in Vault. Claude and others: local speech-to-text, then the text API, then Piper | A provider API key, billed per use | No | Full OS tool integration through contracts |
| Subscription via official CLI | Transcribed text goes to `claude -p` or `codex exec` under `symbi-run`, using the user's own login; replies are spoken by Piper | Claude or ChatGPT plan with CLI login | No | Check each vendor's terms before shipping |
| Vendor voice app | The wake word opens the vendor's own voice mode (for example Claude's or ChatGPT's web app) as a human-face window | Any plan with voice mode | No | The OS passes no data and grants nothing; no OS tool integration |

As far as current docs show, Claude's voice mode lives in Anthropic's apps and there is no Claude speech API, so Claude voice through the OS uses local speech-to-text and text-to-speech around the text API.

### Custom wake words

- In Control Center, Voice, then New wake word: the user types a phrase. Training runs locally in a sandbox with no network, from synthetic speech plus a negative-audio data pack that is downloaded once, pinned and signed.
- openWakeWord's own notebook trains a basic model in under an hour; training time on local CPUs is unmeasured (open question).
- Optional: the user records 10 to 20 samples to train a personal verifier model, a second stage that cuts false activations. It is a noise filter, not authentication.
- The resulting model is signed with the user's local key and pinned by hash (INV-12). Community models come only through the Store with signature and licence checks.
- Defaults: threshold 0.5 and Silero VAD gating on. Target fewer than 0.5 false activations per hour and under 5% misses, as openWakeWord states for its own models.

### Security rules for voice

- **Voice is never authority.** The `voice` principal cannot approve, grant, or drive input; anything beyond its own grants becomes a trustd card confirmed with physical input.
- **Default grants are small:** answer questions, open apps, read the clock and calendar, and call read-only service contracts. Sensitive verbs (send, buy, delete, run) always produce a card.
- **Spoken content is untrusted input,** like a web page: a TV, a video or another person can say the wake word or inject instructions.
- **No mic for anyone else.** Agents get no PipeWire or Pulse capture access; only symbi-voiced gets a capture node, via a WirePlumber access policy (verify the mechanism).
- **Nothing kept by default.** Audio is never written to disk unless the user opts in. Transcripts are journaled as text, following session-class rules.
- **Confidential sessions use the local pipeline only** (INV-8).
- **Rate limits:** a burst of wakes triggers a cool-down and a notification.

### Licensing notes

- openWakeWord code is Apache 2.0, but its pre-trained models are CC BY-NC-SA 4.0 (non-commercial). Do not ship them in the image. Ship one default model trained from data we are licensed to use, or have users train a phrase on first run.
- openWakeWord supports English only, and its last release is v0.6.0 (February 2024). Pin it, vendor it, and budget for maintaining a fork.
- Piper is GPL-3.0-or-later and each voice has its own licence; run it as a separate process and check each bundled voice.

### Acceptance criteria

- [ ] With the mic enabled and no wake word spoken, no audio byte leaves symbi-voiced (verified by instrumentation).
- [ ] A recording of the wake word plus "approve" played from a speaker cannot approve a pending card.
- [ ] The assistant's own speech never triggers a wake.
- [ ] A custom phrase trains and works offline end to end.
- [ ] In a confidential session, choosing an API-key or subscription mode falls back to the local pipeline and says so.

## Repo layout, stack, testing and definition of done

One monorepo, `symbiont-os`, holds everything except the Symbiont runtime itself, which stays upstream at [thirdkeyai/symbiont](https://github.com/thirdkeyai/symbiont) as a pinned dependency (3.0.0, commit deddb9e at the time of writing); runtime changes go upstream first.

```text
symbiont-os/
  crates/
    symbi-common/      ids, journal client, Cedar schema bindings, D-Bus types
    symbi-run/         harness launcher
    symbi-egressd/     egress proxy
    symbi-modeld/      model gateway
    symbi-trustd/      trusted path (TCB)
    symbi-grantd/      grant broker, xdg-desktop-portal backend
    symbi-servicesd/   service broker
    symbi-browserd/    browser broker
    symbi-voiced/      wake word and voice pipeline
    symbi-snapd/       btrfs snapshots
    symbi-bar/         Waybar helper
  apps/
    flight-recorder/
    control-center/
  compositor/
    protocols/         symbi_trusted_surface_v1.xml, symbi_agent_input_v1.xml
    hyprland-patches/  protocol support and input provenance
  policy/              schema.cedarschema, base policies, policy tests
  formal/              TLA+ specs and VERIFY.md (skill-formal-proofs layout)
  harness-profiles/    claude-code/, codex/, pi/, cursor/
  services/            signed service manifests
  skills/              skills shipped with the OS
  voice/               wake-word training pipeline
  image/               BlueBuild recipe, SELinux modules, systemd units
  docs/
```

**Stack**

- Rust for every daemon and CLI (MSRV 1.89, matching Symbiont): tokio, hyper, zbus, `cedar-policy`, wayland-rs.
- C++ only for the Hyprland patches; keep them small enough to review in one sitting.
- Wake-word inference in Rust on ONNX Runtime (`ort`), re-implementing openWakeWord's feature pipeline with parity tests against the Python reference, so no Python runs in the voice service. Python is allowed only in the sandboxed training pipeline.
- UI: Symbiont's A2UI console (Lit/TypeScript), extended and wrapped in a minimal webview shell.

**Testing**

- Unit and property tests (proptest) in every crate.
- An **escape suite** run inside every sandbox tier: direct network, DNS tunnelling, abstract Unix sockets, signals to outside processes, `/proc` and ptrace, uinput, PipeWire capture, reading `~/.ssh`. Every case must fail.
- Fuzzing (cargo-fuzz) for Wayland protocol handlers, the egress proxy parser, manifest and contract parsers.
- VM integration tests: CI boots the built image in QEMU and runs harness, grant, revoke and freeze scenarios.
- TLA+ models, fault checks and trace checks via the `jaschadub/skill-formal-proofs` GitHub Action.

**CI**

- `cargo-deny` and `cargo-vet` on every PR; no new dependency without a pin and a review note.
- Release builds produce the signed image, an SBOM and provenance attestation.
- A nightly job runs the base-image upstream check.

**Definition of done for any task card**

- [ ] Code, tests and docs merged together; the PR lists the invariant IDs touched and the tests that prove them.
- [ ] New journal event types documented in `docs/journal-events.md`.
- [ ] A short threat note in the PR: what an attacker gains if this component is compromised.
- [ ] TCB changes: TLA+ model updated and passing, human review recorded.
- [ ] Escape suite and VM integration tests green.

## Agent handoff protocol and task cards

Every piece of work is a card below; an agent claims one card, works it on its own branch, and hands back a PR that meets the definition of done.

**Protocol**

1. **Claim:** pick a card whose dependencies are Done, set Status to In progress and put your agent name in Owner.
2. **Branch:** `card/<ID>-<short-slug>`, one card per branch.
3. **Read first:** the card's phase section, the invariants it lists, and any TLA+ model it touches.
4. **Tests first:** turn the section's acceptance criteria into failing tests before writing code.
5. **PR:** use the template below; set Status to In review.
6. **Blocked:** set Status to Blocked and add a line to *Risks and open questions*; never work around an invariant.

```markdown
## Card <ID>: <title>
Invariants touched: INV-x, INV-y
Acceptance criteria covered: <list, each linked to its test>
Threat note: <what an attacker gains if this component is compromised>
New journal events: <names, or none>
New dependencies: <crate@version + reason, or none>
Open questions raised: <links, or none>
```

| ID | Card | Depends on | Invariants | Owner | Status |
| --- | --- | --- | --- | --- | --- |
| P0-01 | Repo scaffold, CI, cargo-deny/vet, Cedar schema skeleton | none | INV-12 | Codex | Done |
| P0-02 | TLA+ models: GrantLifecycle, TrustedInput, Freeze, JournalBeforeEffect, SessionClass | none | INV-2, 3, 4, 5, 8, 10 | Codex | Done |
| P0-03 | Base image: BlueBuild recipe on secureblue, cosign signing, SBOM, ported Ombuntu defaults | P0-01 | INV-12 | Codex | In review; verified inputs ready, image qualification pending |
| P0-04 | Qualify Symbiont 3.0's Landlock route on the Fedora Atomic image (platform diagnostic and release driver); retain the report | P0-03 | INV-1, 7 | Codex | Blocked (image/build prerequisites); driver prepared |
| P0-05 | Container tier on Fedora Atomic: moby-engine or Podman for Symbiont's Docker and gVisor routes; qualify the choice | P0-03 | INV-1 |  | Not started |
| P1-01 | symbi-common: principal IDs, D-Bus types, Symbiont API and journal clients | P0-01 | INV-5 |  | Not started |
| P1-02 | symbi-run: desktop launcher over Symbiont's managed CLI route (governed mode) | P1-01, P0-04 | INV-7, 13 |  | Not started |
| P1-03 | symbi-egressd: Symbiont outbound capabilities for APIs; allowlisted CONNECT proxy for workspace mode | P1-01 | INV-1, 5, 6, 7 |  | Not started |
| P1-04 | symbi-modeld: OS gateway on Symbiont's inference broker; Messages, Chat and Responses fronts; virtual keys | P1-01 | INV-5, 6 |  | Not started |
| P1-05 | symbi-modeld routing: session class, LocalGgufRunner and SLM router, per-day spend quotas | P1-04 | INV-8, 12 |  | Not started |
| P1-06 | Claude Code: desktop governed profile and workspace profile with symbi-claude-code hooks | P1-02, P1-04 | INV-6, 13 |  | Not started |
| P1-07 | Codex on the governed route: Responses and Chat broker routes, MCP tool bridge | P1-02, P1-04 | INV-6, 13 |  | Not started |
| P1-08 | Pi adapter for governed and workspace modes | P1-02, P1-04 | INV-6, 13 |  | Not started |
| P1-09 | Cursor: workspace mode only, remote-only, symbi-claude-code Cursor hooks | P1-02, P1-03 | INV-8 |  | Not started |
| P1-10 | Escape suite v1, extending Symbiont's containment and Landlock test drivers | P1-02 | INV-1, 7 |  | Not started |
| P1-11 | Phase 1 release: services shipped in the signed Fedora Atomic image | P1-05 to P1-10, P0-03 | INV-12 |  | Not started |
| P1-12 | Workspace mode: writable project snapshot, diff applied only after approval (terminal relay until trustd) | P1-02, P1-03 | INV-1, 2, 7 |  | Not started |
| P2-02 | Wayland protocols and Hyprland patch: trusted surface, input provenance | P0-02 | INV-4 |  | Not started |
| P2-03 | symbi-trustd: escalation-queue surface, cards, secure attention key, freeze, credential entry | P2-02 | INV-2, 4, 10 |  | Not started |
| P2-04 | symbi-grantd: portal backend writing Symbiont root ceilings and file grants; revocation path | P2-03 | INV-2, 3, 8 |  | Not started |
| P2-05 | symbi\_agent\_input\_v1 and ghost cursor | P2-02 | INV-4 |  | Not started |
| P2-06 | Lock runtime approval routes on the desktop profile: HTTP approve/deny and chat approvals off or trustd-receipt-only | P2-03 | INV-2, 4 |  | Not started |
| P3-01 | symbi-bar and compositor-drawn borders | P2-02 | INV-4 |  | Not started |
| P3-02 | Flight Recorder on A2UI's Run Inspector, plus live timeline | P1-01 | INV-5 |  | Not started |
| P3-03 | Control Center: extend A2UI in a desktop webview shell | P2-04 | INV-2 |  | Not started |
| P4-01 | Service manifests and symbi-servicesd routing | P2-04 | INV-9 |  | Not started |
| P4-02 | symbi-browserd: agent profiles and shared-tab extension | P4-01, P2-05 | INV-4, 9 |  | Not started |
| P4-03 | symbi-service-onboard skill | P4-01 | INV-12 |  | Not started |
| P4-04 | Contract builder screen in Control Center: OpenAPI in, draft ToolClad contracts and manifest out, local signing | P4-03, P3-03 | INV-2, 12 |  | Not started |
| P5-01 | skill.toml on symbi-skill-v2 signatures, instructions-only mode, skill-audit on ClawHavoc | P2-04 | INV-11, 12 |  | Not started |
| P5-02 | Store | P5-01 | INV-12 |  | Not started |
| P5-03 | Policy studio and Z3 property checks | P0-01 | INV-11 |  | Not started |
| P5-04 | symbi-snapd | P2-04 | INV-5 |  | Not started |
| P5-05 | Trace monitor | P0-02, P3-02 | INV-5 |  | Not started |
| P5-06 | Unified kernel images, dm-verity, measured boot | P0-03 | INV-12 |  | Not started |
| P5-07 | OS-shipped skills: symbi-doctor, symbi-policy-author, flight-recorder-review, os-agent-guide | P5-01 | INV-11, 12 |  | Not started |
| V-01 | symbi-voiced: Rust wake-word pipeline and VAD, no network | P2-03 | INV-12, 14 |  | Not started |
| V-02 | Voice pipeline: capture, whisper.cpp, Piper, mic indicator | V-01, P1-05 | INV-8, 14 |  | Not started |
| V-03 | Voice provider modes: API key, subscription CLI, vendor app | V-02 | INV-6, 8 |  | Not started |
| V-04 | Offline custom wake-word trainer and personal verifier | V-01 | INV-12 |  | Not started |
| V-05 | Voice red-team: replayed audio, self-wake, injection via speech | V-02 | INV-14 |  | Not started |

## Risks and open questions

Implementation notes raised during P0: see [docs/open-questions.md](open-questions.md) for CI/review setup, the retired base image, signing setup, unresolved model attributes, build-tool lockfile review, and qualification prerequisites. The original questions below remain open.

The biggest risk is the Hyprland patch for the trusted path; everything else has a known fallback.

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Hyprland moves fast and our protocol patch breaks on rebase | Trusted path unavailable | Keep the patch minimal, propose the protocols upstream, keep the dedicated-session fallback |
| Harness config keys change between releases | Sandbox or routing silently off | Pin harness versions per image; profile tests per version; Claude Code runs with `failIfUnavailable` |
| bubblewrap nested inside gVisor or Firecracker misbehaves | Harness inner sandbox fails | Test matrix per tier; default harnesses to the Landlock tier |
| Fedora rebases every \~6 months | Breakage on upgrade | Automated upstream check; rollback via bootc |
| openWakeWord is unmaintained and its models are non-commercial | Voice feature stalls or can't ship | Rust re-implementation, our own trained default, fork if needed |
| Linux kernel bug breaks isolation | Sandbox escape | Firecracker tier for untrusted agents; seL4 stays a research track |
| Prompt injection steers an agent | Unwanted actions attempted | Contained by the gate, grants and approvals; model output is never authority |
| Proxy hops add latency | Slower agents | Latency budgets in CI; Unix sockets end to end |
| Symbiont does not yet claim containment on every entry point, and Fedora is not in its Linux qualification matrix | A route we rely on may be unqualified on our image | Use only routes Symbiont documents as supported; qualify them on the image (P0-04); fix gaps upstream |

**Open questions**

- [x] Licence for `symbiont-os`: Apache-2.0, selected by the owner on 25 Nov 2026, with Symbiont's copyright notice: Copyright 2024-2026 Jascha Wanger / ThirdKey AI. See [LICENSE](../LICENSE).
- [ ] Do Anthropic's and OpenAI's terms allow subscription logins inside `symbi-run` and as the voice brain via `claude -p` / `codex exec`?
- [ ] Can Pi use Symbiont's MCP tool bridge, so it can run in governed mode?
- [ ] Upstream the Wayland protocols to Hyprland, or carry the patch long-term?
- [ ] Exact WirePlumber mechanism to give only symbi-voiced a capture node.
- [ ] Local CPU and GPU time to train a custom wake word; size and licence of the negative-audio data pack.
- [ ] Default wake phrase, and licensed training data for it.
- [ ] Cedar decision caching strategy in egressd at high connection rates.
- [ ] Product name and signing-key custody (ThirdKey hardware keys?).
- [ ] Symbiont's Docker and gVisor routes need a Docker daemon: layer moby-engine into the image, or qualify Podman's Docker-compatible socket?

## Sources

- [thirdkeyai/symbiont](https://github.com/thirdkeyai/symbiont)
- [Ombuntu](https://ombuntu.org), [privacy and security settings](https://docs.ombuntu.org/privacy.html), [source](https://github.com/Ombuntu/Ombuntu)
- [secureblue](https://github.com/secureblue/secureblue), [wayblue](https://github.com/wayblueorg/wayblue)
- [Debian hyprland package tracker](https://tracker.debian.org/pkg/hyprland)
- [ParticleOS](https://github.com/systemd/particleos)
- [Landlock ABI 6 in Linux 6.12](https://openwall.com/lists/oss-security/2025/05/19/2)
- [Claude Code sandboxing](https://code.claude.com/docs/en/sandboxing)
- [Codex advanced configuration](https://developers.openai.com/codex/config-advanced), [Codex sandbox analysis](https://simonwillison.net/2025/Nov/9/codex-sandbox-investigation/)
- [Cursor: requests go through Cursor's backend](https://forum.cursor.com/t/how-to-use-cursor-directly-with-only-my-model-api/154833)
- [Pi custom models](https://hochej.github.io/pi-mono/coding-agent/models)
- [openWakeWord](https://github.com/dscripka/openWakeWord)
- [Piper (OHF-Voice/piper1-gpl)](https://github.com/OHF-Voice/piper1-gpl)
- [OpenAI Realtime conversations](https://developers.openai.com/api/docs/guides/realtime-conversations)
- [Claude voice mode update, July 2026](https://9to5mac.com/2026/07/23/anthropic-upgrades-claude-voice-mode-with-more-powerful-models/)
- [jaschadub/skill-formal-proofs](https://github.com/jaschadub/skill-formal-proofs)
