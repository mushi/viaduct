output "instance_external_ip" {
  description = "Static public IPv4 of the control-plane node."
  value       = google_compute_address.controlplane.address
}

output "instance_name" {
  description = "Control-plane instance name. Consumed by the Hetzner root (via remote state) as the IAP target for the SPIRE provisioner."
  value       = google_compute_instance.controlplane.name
}

output "zone" {
  description = "Control-plane instance zone. Consumed by the Hetzner root (via remote state) as the IAP target for the SPIRE provisioner."
  value       = google_compute_instance.controlplane.zone
}

output "vault_addr" {
  description = "Vault API address on the WireGuard mesh (public :8200 is closed post-lockdown; reach it as a mesh peer). Set VAULT_ADDR to this; the listener cert lists 10.99.0.1 in its SANs, so verification succeeds with VAULT_CACERT set to the node's /opt/vault/tls/vault.crt."
  value       = "https://10.99.0.1:8200"
}

output "service_account_email" {
  description = "Instance service account (auth to KMS and the snapshot bucket)."
  value       = google_service_account.controlplane.email
}

output "kms_crypto_key_id" {
  description = "KMS key for Vault auto-unseal."
  value       = google_kms_crypto_key.vault_unseal.id
}

output "snapshot_bucket" {
  description = "GCS bucket for Vault Raft snapshots."
  value       = google_storage_bucket.vault_snapshots.name
}
