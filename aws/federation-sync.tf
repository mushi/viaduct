# ── Federation: push the viaduct.aws bundle to GCP after a rebuild ────────────
# A rebuild gives the AWS SPIRE server a fresh datastore, so it mints a new CA and
# its trust bundle changes. https_spiffe federation self-heals normal ca_ttl
# rotations (old and new CA overlap in the bundle), but not a rebuild's
# discontinuous CA: polling can't bootstrap it (validating AWS's new endpoint SVID
# needs the new CA GCP doesn't have yet), so GCP must re-import out-of-band. This
# re-import automates the one manual step
# (README federation step) by reaching the GCP box over IAP, the same pattern the
# Hetzner provisioner uses, and running `spire-server bundle set` there.

data "terraform_remote_state" "gcp" {
  backend = "local"
  config  = { path = "${path.module}/../gcp/terraform.tfstate" }
}

resource "terraform_data" "federation_bundle_to_gcp" {
  # aws_instance.spire.id changes only on a rebuild (terraform apply -replace),
  # so this fires exactly when federation breaks, not on ordinary applies or on
  # ca_ttl rotations (which https_spiffe handles on its own).
  triggers_replace = {
    aws_instance_id = aws_instance.spire.id
  }

  provisioner "local-exec" {
    command     = "${path.module}/scripts/push-bundle-to-gcp.sh"
    interpreter = ["/usr/bin/env", "bash"]
    environment = {
      # The GCP box curls this URL to import the bundle. Post-lockdown the AWS node
      # has no public :8443, so GCP fetches over the mesh (10.99.0.3) via wg0.
      AWS_BUNDLE_URL   = "https://${var.wg_mesh_ip}:${var.bundle_endpoint_port}"
      AWS_TRUST_DOMAIN = var.trust_domain
      GCP_INSTANCE     = data.terraform_remote_state.gcp.outputs.instance_name
      GCP_ZONE         = data.terraform_remote_state.gcp.outputs.zone
      GCP_PROJECT      = var.gcp_project
      GCP_SSH_USER     = var.gcp_ssh_user
      GCP_SSH_KEY_PATH = var.gcp_ssh_key_path
    }
  }

  # wg_mesh_join must run first: GCP reaches AWS at 10.99.0.3 only once this node's
  # wg0 is up and registered with the hub.
  depends_on = [aws_instance.spire, aws_eip.spire, terraform_data.wg_mesh_join]
}
