# ── WireGuard mesh: join the AWS spoke to the GCP hub ─────────────────────────
# After an AWS rebuild (user_data_replace_on_change → new instance id), register
# this node's freshly generated WG public key with the hub and bring up wg0.
# Reaches the box over SSM and the hub over IAP (see scripts/wg-mesh-join.sh).
# data.terraform_remote_state.gcp is declared in federation-sync.tf (same root).

# Let the instance read ONLY its own PSK SecureString parameter (written then
# deleted by the provisioner on each apply), decrypting via the SSM service key.
resource "aws_iam_role_policy" "wg_psk_read" {
  name = "viaduct-wg-psk-read"
  role = aws_iam_role.spire.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = "arn:aws:ssm:${var.region}:*:parameter${var.wg_psk_parameter}"
      },
      {
        Effect    = "Allow"
        Action    = ["kms:Decrypt"]
        Resource  = "*"
        Condition = { StringEquals = { "kms:ViaService" = "ssm.${var.region}.amazonaws.com" } }
      }
    ]
  })
}

resource "null_resource" "wg_mesh_join" {
  # Fires on a rebuild (new instance id), the same trigger as federation-sync,
  # so the spoke re-registers its fresh key exactly when it changes.
  triggers = {
    aws_instance_id = aws_instance.spire.id
  }

  provisioner "local-exec" {
    command     = "${path.module}/scripts/wg-mesh-join.sh"
    interpreter = ["/usr/bin/env", "bash"]
    environment = {
      AWS_REGION      = var.region
      AWS_INSTANCE_ID = aws_instance.spire.id
      GCP_HUB_IP      = var.gcp_control_plane_ip
      WG_PORT         = tostring(var.wg_port)
      WG_MESH_IP      = var.wg_mesh_ip
      PSK_PARAM       = var.wg_psk_parameter

      GCP_INSTANCE     = data.terraform_remote_state.gcp.outputs.instance_name
      GCP_ZONE         = data.terraform_remote_state.gcp.outputs.zone
      GCP_PROJECT      = var.gcp_project
      GCP_SSH_USER     = var.gcp_ssh_user
      GCP_SSH_KEY_PATH = var.gcp_ssh_key_path
    }
  }

  depends_on = [aws_instance.spire, aws_iam_role_policy.wg_psk_read]
}
