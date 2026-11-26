# Hyprland portal candidate inputs

The current images have GTK and wlroots portal backends but do not yet contain
the Hyprland backend. `source-inputs.json` selects the exact portal and toolkit
revisions from the already selected compositor's `flake.lock`. It also binds
the retained full compositor prefix, source/build inputs and native-loading
patch. Both upstream licenses are BSD-3-Clause; their original bytes are kept.

The `reviewed/` files are exact source snapshots used to review dependency and
build entry points. Every file has a SHA-256, byte length and Git blob ID.
`inputs.py` rejects changed sources, widened package requests, stale prefix
bindings, nonregular/escaping/oversized files and altered snapshot bytes before
hosted discovery. Git object identity and these checks are not source audits
or publisher-signature evidence. No release qualification is claimed.

Primary source selections:

- [Hyprland lockfile](https://github.com/hyprwm/Hyprland/blob/11cbc6c577b84ffb1edf4df3fc5b6128c3ae6947/flake.lock).
- [Portal build entry point](https://github.com/hyprwm/xdg-desktop-portal-hyprland/blob/85450448ea40a54ec4f10bd607e68019d8f5cc41/CMakeLists.txt).
- [Share-picker build entry point](https://github.com/hyprwm/xdg-desktop-portal-hyprland/blob/85450448ea40a54ec4f10bd607e68019d8f5cc41/hyprland-share-picker/CMakeLists.txt).
- [Toolkit build entry point](https://github.com/hyprwm/hyprtoolkit/blob/92646e15fb295285b10de626f2d9597216465f7b/CMakeLists.txt).

`build-requirements.json` preserves the compositor's reviewed requirement list
and adds five explicit pkg-config providers: PipeWire, SPA, sdbus-c++, iniparser
and abseil flat_hash_map. This is one signed build closure for the retained
prefix's public dependencies; it does not rebuild the ten existing compositor
source components. Candidate RPMs remain on the hosted runner.

`scripts/check-portal-packages.sh` refuses local execution. On a disposable
GitHub-hosted runner it uses the existing publisher-signature bootstrap and
Fedora RPM resolver. The base root stays read-only; full RPM signatures and
real missing-key/tamper controls must pass, installed packages must match before
and after, and the temporary container must be absent after cleanup. Evidence
and candidate RPMs are retained separately. The workflow has read-only repository
permission and no release environment, signing secrets or publishing rights.

Before the portal can enter a development image:

1. Retain and review the actual signed-RPM result, then pin the exact artifact.
2. Authenticate and reuse the existing full compositor development prefix.
3. Build only the pinned toolkit and portal offline, with upstream version
   constraints enforced and fallback downloads disabled; run applicable tests.
4. Verify exact installation, runtime library closure and original licenses on
   the selected base without replacing its original packages or crypto policy.
5. Qualify actual portal activation, physical selection, capture isolation,
   cancellation and repeated consent with no reusable restore token on a
   booted desktop. Packaging and command-line checks cannot prove these.
