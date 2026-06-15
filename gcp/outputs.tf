output "instance_external_ip" {
  description = "Public IPv4 of the control-plane node."
  value       = google_compute_instance.controlplane.network_interface[0].access_config[0].nat_ip
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
