# ── Cross-cloud CA refresh (fingerprint sync without a rebuild) ───────────────
# GCP's self-signed Vault listener cert rotates on every GCP rebuild, so pinning its
# fingerprint goes stale. Instead, on every apply, read the CURRENT fingerprint from
# the GCP box over IAP (trusted) and drive crosscloud-bootstrap on the AWS box over
# SSM (see scripts/crosscloud-refresh.sh). So a GCP rebuild is followed by a plain
# `terraform apply` here — a refresh, not an AWS instance rebuild. always_run makes
# that post-GCP-rebuild apply pick up the new cert; the bootstrap is idempotent when
# nothing changed. data.terraform_remote_state.gcp is declared in federation-sync.tf.
resource "terraform_data" "crosscloud_refresh" {
  triggers_replace = {
    always_run = timestamp()
  }

  provisioner "local-exec" {
    command     = "${path.module}/scripts/crosscloud-refresh.sh"
    interpreter = ["/usr/bin/env", "bash"]
    environment = {
      AWS_REGION       = var.region
      AWS_INSTANCE_ID  = aws_instance.spire.id
      GCP_MESH_IP      = var.wg_hub_ip
      GCP_TRUST_DOMAIN = var.gcp_trust_domain

      GCP_INSTANCE     = data.terraform_remote_state.gcp.outputs.instance_name
      GCP_ZONE         = data.terraform_remote_state.gcp.outputs.zone
      GCP_PROJECT      = var.gcp_project
      GCP_SSH_USER     = var.gcp_ssh_user
      GCP_SSH_KEY_PATH = var.gcp_ssh_key_path
    }
  }

  # Must run AFTER the mesh is up: crosscloud-bootstrap now dials the hub's mesh IP
  # (GCP_MESH_IP → crosscloud.env GCP_IP) for the federation bundle + Vault CA, so
  # wg0 has to exist first. wg_mesh_join brings it up.
  depends_on = [aws_instance.spire, terraform_data.wg_mesh_join]
}
