# ── Pre-replace backup ────────────────────────────────────────────────────────
# Before the control-plane instance is replaced or destroyed, capture a FRESH
# Vault + SPIRE snapshot to GCS so the rebuilt instance restores the latest state
# rather than the last weekly snapshot (startup.sh §6a consumes it).
#
# Ordering: this resource depends on the instance (its triggers read the
# instance's attributes), so on a replace Terraform destroys THIS first (running
# the backup) while the old instance is still alive, then destroys the instance.
#
# Keyed on instance_id, not timestamp(): the backup must run only when the
# instance is actually being replaced/destroyed, never on a plain metadata apply.
# Destroy-time provisioners may reference only `self`, so the script path and all
# the values it needs are captured in triggers_replace and read back via
# self.triggers_replace.
resource "terraform_data" "prereplace_backup" {
  triggers_replace = {
    instance_id = google_compute_instance.controlplane.id
    instance    = google_compute_instance.controlplane.name
    zone        = google_compute_instance.controlplane.zone
    project     = var.project_id
    ssh_user    = var.ssh_user
    ssh_key     = var.ssh_private_key_path
    script      = "${path.module}/scripts/prereplace-backup.sh"
  }

  provisioner "local-exec" {
    when        = destroy
    command     = self.triggers_replace.script
    interpreter = ["/usr/bin/env", "bash"]
    environment = {
      GCP_INSTANCE     = self.triggers_replace.instance
      GCP_ZONE         = self.triggers_replace.zone
      GCP_PROJECT      = self.triggers_replace.project
      GCP_SSH_USER     = self.triggers_replace.ssh_user
      GCP_SSH_KEY_PATH = self.triggers_replace.ssh_key
    }
  }
}
