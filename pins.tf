# Every downloaded artifact is pinned once, in pins.json. Pins are not secrets, so they
# are committed and reviewed like code, and the weekly pins workflow can update them.
#
# A recorded digest is trust-on-first-use: cloud-init aborts if a release or CDN serves
# different bytes AFTER the pin was recorded, but a release that was already malicious
# when pinned passes. Catching that needs upstream provenance (SLSA / cosign).
locals {
  pins = jsondecode(file("${path.module}/pins.json"))
}
