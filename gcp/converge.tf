# ── Control-plane convergence ─────────────────────────────────────────────────
# Makes `terraform apply` change the RUNNING control plane, not just its next boot.
#
# GCE executes `startup-script` metadata once, at boot. Terraform can update that
# metadata, but nothing re-runs it, so an apply that edits the script converges the
# next reboot and reports success against a box still executing the previous one.
# On 2026-09-04 a corrected Alloy config sat in metadata for hours while the node
# kept the broken one, and the apply that delivered it exited 0 — the same class of
# gap as `ignore_changes = [user_data]` on the Hetzner and AWS roots.
#
# The trigger hashes the whole rendered metadata map rather than just the script
# file, because startup.sh reads its configuration from the other metadata keys at
# runtime: changing `alloy_amd64_sha256` or `spire_version` in tfvars alters what a
# run does without altering a single byte of the script.
#
# Ordering: converge runs after the instance settles and before the readiness gate,
# so `controlplane_ready` reports on the configuration this apply actually
# delivered. If the startup script fails, converge fails and takes the apply with
# it, which is the entire point.
resource "terraform_data" "controlplane_converge" {
  triggers_replace = {
    metadata = sha256(jsonencode(google_compute_instance.controlplane.metadata))
  }

  provisioner "local-exec" {
    command     = "${path.module}/scripts/converge-controlplane.sh"
    interpreter = ["/usr/bin/env", "bash"]
    environment = {
      GCP_INSTANCE     = google_compute_instance.controlplane.name
      GCP_ZONE         = google_compute_instance.controlplane.zone
      GCP_PROJECT      = var.project_id
      GCP_SSH_USER     = var.ssh_user
      GCP_SSH_KEY_PATH = var.ssh_private_key_path
    }
  }

  depends_on = [google_compute_instance.controlplane]
}
