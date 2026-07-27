# Control-plane recovery after an instance rebuild

Recovery is **automatic**. `terraform apply -replace=google_compute_instance.controlplane`
recreates the control-plane instance; `startup.sh` restores Vault and SPIRE from the latest
GCS backup on first boot, and the readiness gate holds the apply until Vault is unsealed and
the SPIRE server is active. No manual steps.

## How it works

Durable across a rebuild (`prevent_destroy` in `main.tf`): the GCP KMS unseal key and the
snapshot bucket. The boot disk is disposable.

1. **Fresh backup before teardown.** `null_resource.prereplace_backup` (a destroy-time
   provisioner in `backup.tf`) runs `vault-snapshot.service` on the old instance while it is
   still alive, so `vault.snap` and `spire-data.tar.gz` in the bucket hold the latest state.
2. **Restore on first boot** (`startup.sh` §6a, when Vault is uninitialised and a backup is
   present): init a temporary root token, then `vault operator raft snapshot restore -force`
   of `vault.snap` (KMS re-unseals the restored data); log in with the box's own GCE identity
   (the `restore-agent` gcp-auth role, itself restored in the snapshot) to regenerate the
   AppRole `secret-id`s that lived on the ephemeral disk; extract `spire-data.tar.gz` into
   `/opt/spire/data/server` (datastore + `keys.json`).

Vault's PKI root and the SPIRE datastore both return, so the rebuilt SPIRE server keeps the
**same** trust-domain CA: agents keep trusting it and federation stays intact, with no
re-attestation.

## Backups

`vault-snapshot.service` writes `vault.snap` (Vault Raft) and `spire-data.tar.gz` (a
transaction-consistent SPIRE datastore copy plus `keys.json`) to the bucket. It runs weekly
on `vault-snapshot.timer` and once more, on demand, just before every replace (step 1). The
bucket keeps the last 3 versions of each object.

## Break-glass (manual restore)

Only if the automatic restore fails. Reach the box over IAP
(`gcloud compute ssh viaduct-controlplane --tunnel-through-iap`) and run the same sequence as
`startup.sh` §6a, authenticating after the restore with your **offline** recovery keys (the
temporary init token is invalidated by the restore). Do not run `vault operator init` and
stop there: that forks a new empty Vault instead of restoring.
