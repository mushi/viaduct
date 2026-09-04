# ── Control-plane readiness gate ──────────────────────────────────────────────
# After the instance is created or modified, poll it over IAP until Vault is
# unsealed and the SPIRE server is active, then print a confirmation. This makes
# `terraform apply` block until the control plane is genuinely ready, so a deploy
# is simply: apply gcp/ (wait for the "ready" line), then apply the Hetzner root.
#
# triggers.always_run = timestamp() runs the check on every apply on purpose: it
# is the readiness confirmation, and a stop/start (e.g. the secure-boot change)
# modifies the instance in place without changing its id, so keying on the id
# would miss exactly the case this exists for. Every plan therefore shows this
# resource as replaced; that is expected. Skip it with -target for a pure
# metadata-only apply if ever needed. The check only reads state; it never
# modifies the instance.
resource "terraform_data" "controlplane_ready" {
  triggers_replace = {
    always_run = timestamp()
  }

  provisioner "local-exec" {
    command     = "${path.module}/scripts/wait-controlplane-ready.sh"
    interpreter = ["/usr/bin/env", "bash"]
    environment = {
      GCP_INSTANCE     = google_compute_instance.controlplane.name
      GCP_ZONE         = google_compute_instance.controlplane.zone
      GCP_PROJECT      = var.project_id
      GCP_SSH_USER     = var.ssh_user
      GCP_SSH_KEY_PATH = var.ssh_private_key_path
    }
  }

  # After convergence, so the readiness this reports is the configuration THIS
  # apply delivered rather than whatever the box happened to boot with.
  depends_on = [
    google_compute_instance.controlplane,
    terraform_data.controlplane_converge,
  ]
}
