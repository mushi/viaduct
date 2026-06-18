# Vault restore after an instance rebuild

The control-plane boot disk is ephemeral: a rebuilt instance starts with an empty
Vault Raft store. Restore from the latest GCS snapshot.

This works because the KMS unseal key and the snapshot bucket are durable
(`prevent_destroy`), so the snapshot decrypts and Vault auto-unseals.

Snapshots are weekly (`vault-snapshot.timer`), fixed key `gs://<bucket>/vault.snap`,
last 3 versions retained.

## Steps

1. Rebuild the instance:
   ```sh
   terraform apply -replace=google_compute_instance.controlplane
   ```
   Vault comes up auto-unsealed but **uninitialised**.

2. SSH in (`viaduct@<ip>`), then:
   ```sh
   export VAULT_ADDR=https://127.0.0.1:8200 VAULT_SKIP_VERIFY=true
   ```

3. Initialise the fresh cluster for a temporary root token (discarded in step 6):
   ```sh
   vault operator init     # keep the temp root token for step 5 only
   ```

4. Download the latest snapshot:
   ```sh
   gcloud storage cp gs://<bucket>/vault.snap /tmp/vault.snap
   ```

5. Restore (force), using the temp root token:
   ```sh
   VAULT_TOKEN=<temp-root> vault operator raft snapshot restore -force /tmp/vault.snap
   rm -f /tmp/vault.snap
   ```

6. Vault now holds the restored data. Authenticate with your **original** root
   token / recovery keys from 1Password — the temp init token from step 3 is
   invalidated by the restore.

7. Re-place the AppRole secret_ids (the on-disk files were on the ephemeral disk;
   the roles/policies/PKI themselves came back with the snapshot). With the
   original root token:
   ```sh
   # SPIRE
   vault write -f -field=secret_id auth/approle/role/spire-server/secret-id
   #  -> /opt/spire/conf/server/spire.env  as  VAULT_APPROLE_SECRET_ID=<value>  (0600 spire)
   # Snapshot job
   vault write -f -field=secret_id auth/approle/role/snapshot-saver/secret-id
   #  -> /opt/vault-snapshot/secret-id      (raw value, 0600 root)
   ```

8. Restart consumers:
   ```sh
   sudo systemctl restart spire-server
   ```

## Note
The PKI root CA private key is the critical durable asset. As long as snapshots
exist (or the root CA is otherwise backed up), a rebuild is recoverable without
re-issuing the trust bundle to agents.
