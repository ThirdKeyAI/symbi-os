# Sources for the initial image defaults

The project remains Apache-2.0. Adapted third-party portions retain these MIT
notices; the generated recipe installs both notices with the project's license.

| Source | Immutable revision | Included material |
| --- | --- | --- |
| [Ombuntu](https://github.com/Ombuntu/Ombuntu/tree/8f2085cb73520fc3558f1248dadd1fca5e69cfcc) | `8f2085cb73520fc3558f1248dadd1fca5e69cfcc` | Original browser privacy JSON and MIT license under `vendor/ombuntu`; adapted browser policies, probe/telemetry opt-outs and portal default |
| [Omarchy v3.8.4](https://github.com/omacom/omarchy/tree/8fcc9d6048af4cb0e3af8512c78049857a3b53dd) | `8fcc9d6048af4cb0e3af8512c78049857a3b53dd` | Original Hyprland input, Waybar and Walker configs and MIT license under `vendor/omarchy`; reduced local defaults in the overlay |
| [BlueBuild experimental tool build](https://github.com/blue-build/cli/tree/a654ee8810c637aa00356999488e97259061275d) | `a654ee8810c637aa00356999488e97259061275d` | Post-v0.9.42 source for hosted recipe-v2 compatibility checks; Apache-2.0, no vendored executable or OS payload |
| [Cosign v3.1.5](https://github.com/sigstore/cosign/tree/e5a0818ca5729481095773409e9c1b60cc278e8d) | `e5a0818ca5729481095773409e9c1b60cc278e8d` | Authenticated external tool for base-signature verification and OS key generation; no executable vendored or shipped |
| [secureblue publisher key](https://github.com/secureblue/secureblue/blob/353366bb6d031e66fc565b0b101a8a069f32fcdb/cosign.pub) | `353366bb6d031e66fc565b0b101a8a069f32fcdb` | Public verification key in `keys/secureblue-2026.pub`; exact verified image references in `base-images.json` |

Omarchy's revision is the one pinned by Ombuntu's `install/lib.sh`, not the
current moving Omarchy branch. `vendor/SHA256SUMS` binds the original copied
files; `scripts/check-image.sh` checks it offline. Changes to the adapted files
are reviewable alongside the originals.

The overlay does not import the upstream installers, hook/menu extension
loaders, web search, remote themes, weather polling or browser extension
auto-install lists. It keeps a small local desktop configuration. New commands
and the appearance stylesheet are project code. No vendored script executes at
login or image build time.

Firefox uses its documented system path `/etc/firefox/policies/policies.json`.
Chromium uses `/etc/chromium/policies/managed`; the selected base's actual browser
and Flatpak policy integration must be qualified separately. Privacy defaults do
not turn off browser security updates. The portal setting changes the default
choice; it does not prove that explicit restore-token requests are refused.
