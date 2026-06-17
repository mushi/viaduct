output "instance_external_ip" {
  description = "Static public IPv4 of the control-plane node."
  value       = google_compute_address.controlplane.address
}

output "vault_addr" {
  description = "Vault API address. Set VAULT_ADDR to this; the listener cert is self-signed (VAULT_CACERT=/opt/vault/tls/vault.crt on the node)."
  value       = "https://${google_compute_address.controlplane.address}:8200"
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
