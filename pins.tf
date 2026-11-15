# Every downloaded artifact and booted image is pinned once, in the repo-root pins.json,
# shared by all three roots and the AWS manifests. Pins are not secrets, so they are
# committed and reviewed like code; refresh with scripts/get-checksums.sh --write.
locals {
  pins = jsondecode(file("${path.module}/pins.json"))
}
