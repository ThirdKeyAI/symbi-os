# Image trust roots

Commit only public verification keys here, with their SHA-256 in the reviewed
base/release configuration. Private ThirdKey signing keys belong in the selected
hardware/KMS signing service or protected runner secret storage, never this tree.

There is no selected replacement base or release trust root yet (OQ-03, OQ-07).
No development key substitutes for a ThirdKey release key.
