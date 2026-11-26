# Nerd Font candidate intake

The owner selected JetBrainsMono Nerd Font plus the Nerd Fonts symbols font for
the Ombuntu-compatible desktop profile. `inputs.json` binds Nerd Fonts v3.5.1,
its exact source revision, immutable GitHub release asset IDs, sizes and API
SHA-256 digests. Reviewed OFL, MIT and Font Logos Unlicense notices are retained
with their hashes. The upstream license audit is preserved unmodified; its
older “Unlicensed” Font Logos row is supplemented by the exact upstream
Unlicense text and revision reviewed for this candidate.

Release assets do not have a detached publisher signature. The intake therefore
makes a narrower claim than the Kitty bundle workflow: exact pinned public bytes
and source/release metadata, not publisher-signature verification or reproducible
source/binary equivalence. Fonts are not selected or installed by this step.

Hosted CI downloads the two archives and the release checksum index in a
disposable, zero-capability, no-new-privileges service with one CPU, 512 MiB
memory, zero swap, 32 tasks and a ten-minute deadline. It checks exact size and
SHA-256, requires the release index to agree, then streams the tar archives
without extracting them. It rejects absolute, nested, traversing, duplicate,
linked, special, set-ID, control-character, unknown and oversized members. Font
members need a recognized SFNT/OpenType header; required regular/mono faces and
license/readme files must be present. The inspector does not invoke fontconfig,
FreeType or any candidate parser.

The pin document uses duplicate-rejecting JSON decoding. The runtime requires
the exact three asset names and order, exact five notice paths under the local
font-license directory, exact metadata fields, and a final HTTPS GitHub or
GitHubusercontent delivery host. Hash and size checks still bind the response
bytes after redirects. These checks prevent ambiguous keys, path substitution
and alternate delivery hosts from changing the reviewed intake.

The exact public archives and complete hash inventories are retained for a later
native font-parser/rendering review. Before image integration, reconcile the
member inventory with the pinned source, review every glyph notice, run bounded
fontconfig/FreeType tests in both approved bases, select the installed faces,
and exercise Kitty, Walker and Waybar rendering. The final signed image and SBOM
must carry the notices. This intake is not desktop, security or OS qualification.
