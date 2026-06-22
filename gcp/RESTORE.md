# Vault restore from snapshot after an instance rebuild

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
   read -rsp 'temp root token: ' VAULT_TOKEN; export VAULT_TOKEN; echo   # off the command line / history
   vault operator raft snapshot restore -force /tmp/vault.snap
   rm -f /tmp/vault.snap
   ```

6. Vault now holds the restored data. Authenticate with your **original** root
   token / recovery keys from the safe place where you stored them — the temp init token from step 3 is
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
The PKI root CA private key (in Vault) is the critical durable asset. Because the snapshot
restores it, the rebuilt SPIRE server's new intermediate chains to the **same** root — so
agents keep trusting the trust domain and don't need a new CA bundle.

## SPIRE state after a rebuild
The Vault snapshot does **not** contain SPIRE server state. SPIRE's datastore
(`/opt/spire/data/server/datastore.sqlite3` — registration entries + federated bundles) and
its KeyManager keys (`keys.json`) live on the **ephemeral boot disk** and are lost on a
rebuild. After the Vault restore above, also:

1. **Re-import the AWS federated bundle** (TOFU, as in first-time federation). GCP's own
   bundle is unchanged (same root), so the AWS side needs nothing:
   ```sh
   curl -sk https://<aws-ip>:8443 | sudo spire-server bundle set -format spiffe -id spiffe://viaduct.aws
   ```
2. **Recreate registration entries**, e.g. the Hetzner workload:
   ```sh
   sudo spire-server entry create \
     -parentID spiffe://viaduct.gcp/hetzner \
     -spiffeID spiffe://viaduct.gcp/hetzner/vault-agent \
     -selector unix:uid:994 -dns vault-agent.hetzner
   ```
3. **Re-attest the Hetzner agent** — its `join_token` is single-use and its server-side
   record is gone. Issue a fresh token and restart `spire-agent` on Hetzner:
   ```sh
   sudo spire-server token generate -spiffeID spiffe://viaduct.gcp/hetzner
   ```

For a lab this manual recovery is fine; to avoid it, put `/opt/spire/data` on a persistent
disk or back the datastore up alongside the Vault snapshot.
