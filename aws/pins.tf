# Every downloaded artifact and booted image is pinned once, in the repo-root pins.json,
# shared by all three roots and the AWS manifests. Pins are not secrets, so they are
# committed and reviewed like code; refresh with scripts/get-checksums.sh --write.
locals {
  pins = jsondecode(file("${path.module}/../pins.json"))
}

# The manifests reference images and the Conduit binary through these, so their digests
# live in pins.json with everything else. Each image renders as "name@digest # tag".
locals {
  k8s_pins = {
    images               = { for k, v in local.pins.images : k => "${v.name}@${v.digest} # ${v.tag}" }
    conduit_version      = local.pins.conduit.version
    conduit_arm64_sha256 = local.pins.conduit.sha256["linux-arm64"]
  }
}
