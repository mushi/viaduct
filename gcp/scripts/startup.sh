#!/usr/bin/env bash
# Viaduct GCP control-plane startup script — Phase 2a: swap + Vault.
#
# Runs on every boot (GCE startup-script). Idempotent. Reads its config from
# instance metadata so this file stays plain bash (no Terraform templating).
#
# It installs and configures Vault (Raft storage, GCP KMS auto-unseal) and
# starts it SEALED + UNINITIALISED. The operator then runs `vault operator init`
# once over SSH and stores the recovery keys + root token in a safe place offline
# (e.g. a password manager). Vault auto-unseals via KMS thereafter.
set -euo pipefail

# The Google Cloud CLI ships as a snap at /snap/bin/gcloud, which is NOT on the
# non-interactive startup-script PATH (systemd default: /usr/sbin:/usr/bin:...).
# Without this, every `gcloud` call here (snapshot restore below, backup job)
# fails with "command not found" and is silently swallowed inside `if` guards.
export PATH="/snap/bin:$PATH"

md() { curl -sf -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/$1"; }

REGION="$(md instance/attributes/region)"
KEYRING="$(md instance/attributes/kms-keyring)"
CRYPTOKEY="$(md instance/attributes/kms-cryptokey)"
VAULT_VERSION="$(md instance/attributes/vault-version)"
VAULT_IP="$(md instance/attributes/vault-addr-ip)"
PROJECT="$(md project/project-id)"

# Hub address on the private WireGuard mesh (10.99.0.0/24). A fixed architectural
# constant — spokes dial the hub here once public control-plane ingress is dropped,
# so it must be in the Vault listener cert SANs (§3) and is the hub's wg0 address (§8).
WG_HUB_MESH_IP="10.99.0.1"

# Install the operator's one-time Vault bootstrap helper (run once after
# `vault operator init`; see the runbook). Shipped via metadata so it stays a
# standalone, reviewable file in gcp/scripts/. Absent on standalone deploys.
BVS="$(md instance/attributes/bootstrap-vault-script || true)"
if [ -n "$BVS" ]; then
  printf '%s' "$BVS" > /usr/local/bin/bootstrap-vault.sh
  chmod 0755 /usr/local/bin/bootstrap-vault.sh
fi
unset BVS

# ── 1. No swap (deliberate) ──────────────────────────────────────────────────
# With mlock disabled (see vault.hcl), swap would be a path for in-memory
# secrets to reach the disk in plaintext. zram (RAM-backed swap) is unavailable
# — the GCE kernel does not ship the zram module — and an encrypted disk swap
# adds fragility, so we run swapless. Vault (~190 MB) + SPIRE (~150 MB) + OS
# (~250 MB) fit within the 955 MB of RAM.

# ── 2. Install Vault (HashiCorp apt repo, GPG-signed, pinned + held) ─────────
if ! command -v vault >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor -o /etc/apt/keyrings/hashicorp.gpg
  . /etc/os-release
  echo "deb [signed-by=/etc/apt/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com ${VERSION_CODENAME} main" \
    > /etc/apt/sources.list.d/hashicorp.list
  apt-get update -y
  apt-get install -y "vault=${VAULT_VERSION}"
  apt-mark hold vault
fi

# ── 3. TLS for the Vault listener (self-signed; SAN = static IP + mesh IP) ────
# Agents trust this cert as their VAULT_CACERT. The static IP keeps the SAN
# stable across instance rebuilds; the mesh IP (10.99.0.1) lets cross-node
# clients verify Vault over the WireGuard overlay once public :8200 is dropped.
mkdir -p /opt/vault/tls
if [ ! -f /opt/vault/tls/vault.crt ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout /opt/vault/tls/vault.key -out /opt/vault/tls/vault.crt -days 3650 \
    -subj "/CN=viaduct-vault" \
    -addext "subjectAltName=IP:${VAULT_IP},IP:${WG_HUB_MESH_IP},IP:127.0.0.1"
fi

# ── 4. Vault config: Raft storage + GCP KMS auto-unseal ──────────────────────
# The gcpckms seal authenticates with the instance's own service account
# (ADC via the metadata server) — no static key on disk.
mkdir -p /opt/vault/data
cat > /etc/vault.d/vault.hcl <<EOF
ui = false

# mlock is DISABLED: on this
# 1 GB host mlock inflated Vault's RSS to ~530 MB (Go heap arenas locked
# resident); disabling it drops RSS to ~190 MB, which fits the box. Safe because
# this host has NO swap (see startup.sh).
disable_mlock = true

storage "raft" {
  path    = "/opt/vault/data"
  node_id = "viaduct-controlplane"
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/opt/vault/tls/vault.crt"
  tls_key_file  = "/opt/vault/tls/vault.key"
}

seal "gcpckms" {
  project    = "${PROJECT}"
  region     = "${REGION}"
  key_ring   = "${KEYRING}"
  crypto_key = "${CRYPTOKEY}"
}

api_addr     = "https://${VAULT_IP}:8200"
cluster_addr = "https://${VAULT_IP}:8201"
EOF

chown -R vault:vault /opt/vault /etc/vault.d
chmod 600 /opt/vault/tls/vault.key
chmod 640 /etc/vault.d/vault.hcl

# ── 5. Start Vault (comes up sealed + uninitialised on first boot) ───────────
systemctl enable vault
systemctl restart vault

# ── 6. SPIRE server ──────────────────────────────────────────────────────────
SPIRE_VERSION="$(md instance/attributes/spire-version)"
SPIRE_SHA256="$(md instance/attributes/spire-sha256)"
SPIRE_ROLE_ID="$(md instance/attributes/spire-approle-role-id)"
TRUST_DOMAIN="$(md instance/attributes/trust-domain)"

if ! command -v spire-server >/dev/null 2>&1; then
  TARBALL="spire-${SPIRE_VERSION}-linux-amd64-musl.tar.gz"
  curl -fsSL -o "/tmp/${TARBALL}" \
    "https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/${TARBALL}"
  echo "${SPIRE_SHA256}  /tmp/${TARBALL}" | sha256sum -c -
  tar -xzf "/tmp/${TARBALL}" -C /tmp
  install -m 0755 "/tmp/spire-${SPIRE_VERSION}/bin/spire-server" /usr/local/bin/spire-server
  rm -rf "/tmp/spire-${SPIRE_VERSION}" "/tmp/${TARBALL}"
fi

id spire >/dev/null 2>&1 || useradd --system --home-dir /opt/spire --shell /usr/sbin/nologin spire
mkdir -p /opt/spire/conf/server /opt/spire/data/server

# ── 6a. Restore from backup on a rebuilt instance ─────────────────────────────
# A rebuilt node starts with an empty Vault Raft store and empty SPIRE data. If a
# backup exists in GCS, restore both so the control plane comes back whole with no
# manual runbook. Guard: only when Vault is uninitialised (a fresh instance) AND a
# backup is present, so a normal reboot (data intact on the persistent boot disk)
# and the first-ever deploy (no backup yet) are both left untouched.
command -v jq >/dev/null || apt-get install -y jq
# Loopback to the co-located Vault. The self-signed listener cert lists 127.0.0.1
# in its SANs, so CACERT verification succeeds (same cert the agents trust).
export VAULT_ADDR="https://127.0.0.1:8200" VAULT_CACERT="/opt/vault/tls/vault.crt"
BUCKET="$(md instance/attributes/snapshot-bucket)"

# Wait for Vault's listener to actually answer. `vault status` exits non-zero
# while sealed/uninitialised, so we cannot gate on its exit code; instead break
# as soon as -format=json returns non-empty output (listener up), up to ~120s.
# Without this the gate can read an empty status on a slow boot and skip the
# restore, leaving the node fresh and uninitialised.
VS_JSON=""
for _ in $(seq 1 60); do
  VS_JSON="$(vault status -format=json 2>/dev/null || true)"
  [ -n "$VS_JSON" ] && break
  sleep 2
done
# NB: use has()/tostring, not `.initialized // "unknown"` — jq's `//` treats a
# boolean false as "no value", so `false // "unknown"` yields "unknown", and a
# freshly rebuilt Vault is always initialized=false. That bug skipped the restore
# on every boot.
VAULT_INITIALISED="$(printf '%s' "$VS_JSON" | jq -r 'if has("initialized") then (.initialized | tostring) else "unknown" end' 2>/dev/null || echo unknown)"
echo "restore-gate: vault initialised=${VAULT_INITIALISED}, bucket=${BUCKET}"

if [ "$VAULT_INITIALISED" = "false" ] && gcloud storage ls "gs://$BUCKET/vault.snap" >/dev/null 2>&1; then
  echo "Rebuilt instance with a backup present — restoring Vault + SPIRE."

  # Vault: init a fresh cluster for a temporary root token, then restore the
  # snapshot (which invalidates that token). KMS auto-unseal re-applies to the
  # restored data. This is the automatic recovery path (see docs/RUNBOOK.md).
  TMP_ROOT="$(vault operator init -format=json | jq -r '.root_token')"
  gcloud storage cp "gs://$BUCKET/vault.snap" /tmp/vault.snap
  VAULT_TOKEN="$TMP_ROOT" vault operator raft snapshot restore -force /tmp/vault.snap
  rm -f /tmp/vault.snap

  # Regenerate the AppRole secret-ids (they lived on the ephemeral disk) with the
  # scoped restore-agent gcp-auth role, which came back in the snapshot. Login is
  # by the box's own GCE identity, no bootstrap secret.
  mkdir -p /opt/vault-snapshot /opt/vault-certrole
  chmod 0700 /opt/vault-snapshot /opt/vault-certrole
  # vault CLI requires flags (-method, -token-only) BEFORE positional key=value
  # args (role=, type=); -token-only after them is rejected as a bad key/value pair.
  VAULT_TOKEN="$(vault login -method=gcp -token-only role=restore-agent type=gce)"
  export VAULT_TOKEN
  SID="$(vault write -f -field=secret_id auth/approle/role/spire-server/secret-id)"
  install -o spire -g spire -m 0600 /dev/null /opt/spire/conf/server/spire.env
  echo "VAULT_APPROLE_SECRET_ID=$SID" > /opt/spire/conf/server/spire.env
  vault write -f -field=secret_id auth/approle/role/snapshot-saver/secret-id > /opt/vault-snapshot/secret-id
  vault write -f -field=secret_id auth/approle/role/aws-certrole-refresh/secret-id > /opt/vault-certrole/secret-id
  chmod 0600 /opt/vault-snapshot/secret-id /opt/vault-certrole/secret-id
  unset VAULT_TOKEN SID

  # SPIRE: restore the datastore + keys so the CA and registration/federation
  # state are unchanged (no re-attestation). Ownership is fixed by §6's chown.
  # Current backups are KMS-encrypted (the archive carries the viaduct.gcp CA private
  # keys). The plaintext name is still accepted so a bucket written before this change
  # remains restorable — without that fallback, a rebuild against an older backup would
  # silently come up with no SPIRE state.
  if gcloud storage ls "gs://$BUCKET/spire-data.tar.gz.enc" >/dev/null 2>&1; then
    gcloud storage cp "gs://$BUCKET/spire-data.tar.gz.enc" /tmp/spire-data.tar.gz.enc
    gcloud kms decrypt \
      --location "$REGION" --keyring "$KEYRING" --key "$CRYPTOKEY" \
      --ciphertext-file /tmp/spire-data.tar.gz.enc \
      --plaintext-file /tmp/spire-data.tar.gz
    rm -f /tmp/spire-data.tar.gz.enc
    tar -C /opt/spire/data/server -xzf /tmp/spire-data.tar.gz
    rm -f /tmp/spire-data.tar.gz
  elif gcloud storage ls "gs://$BUCKET/spire-data.tar.gz" >/dev/null 2>&1; then
    echo "restore: legacy unencrypted spire-data.tar.gz found; restoring, next snapshot will be encrypted"
    gcloud storage cp "gs://$BUCKET/spire-data.tar.gz" /tmp/spire-data.tar.gz
    tar -C /opt/spire/data/server -xzf /tmp/spire-data.tar.gz
    rm -f /tmp/spire-data.tar.gz
  fi
fi

# Public Vault CA cert, readable by spire (UpstreamAuthority TLS verification).
install -m 0644 /opt/vault/tls/vault.crt /opt/spire/conf/server/vault-ca.crt

# Cross-cloud SPIRE federation with viaduct.aws. Built here (not just live) because
# GCP regenerates server.conf on every boot — without this a reboot drops federation.
# Only emitted when the AWS SPIRE server IP is provided (standalone deploys stay clean).
AWS_SPIRE_IP="$(md instance/attributes/aws-spire-ip || true)"
FEDERATION_BLOCK=""
if [ -n "$AWS_SPIRE_IP" ]; then
  FEDERATION_BLOCK=$(cat <<FED

  federation {
    bundle_endpoint {
      address = "0.0.0.0"
      port    = 8443
      profile "https_spiffe" {}
    }
    federates_with "viaduct.aws" {
      bundle_endpoint_url = "https://${AWS_SPIRE_IP}:8443"
      bundle_endpoint_profile "https_spiffe" {
        endpoint_spiffe_id = "spiffe://viaduct.aws/spire/server"
      }
    }
  }
FED
)
fi

cat > /opt/spire/conf/server/server.conf <<EOF
server {
  bind_address          = "0.0.0.0"
  bind_port             = "8081"
  trust_domain          = "${TRUST_DOMAIN}"
  data_dir              = "/opt/spire/data/server"
  log_level             = "INFO"
  ca_ttl                = "168h"
  default_x509_svid_ttl = "1h"
${FEDERATION_BLOCK}
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type     = "sqlite3"
      connection_string = "/opt/spire/data/server/datastore.sqlite3"
    }
  }

  KeyManager "disk" {
    plugin_data { keys_path = "/opt/spire/data/server/keys.json" }
  }

  NodeAttestor "join_token" {
    plugin_data {}
  }

  UpstreamAuthority "vault" {
    plugin_data {
      vault_addr      = "https://127.0.0.1:8200"
      pki_mount_point = "pki"
      ca_cert_path    = "/opt/spire/conf/server/vault-ca.crt"
      approle_auth {
        approle_id = "${SPIRE_ROLE_ID}"
        # approle_secret_id is supplied via VAULT_APPROLE_SECRET_ID
        # (systemd EnvironmentFile /opt/spire/conf/server/spire.env, 0600).
      }
    }
  }
}
EOF

cat > /etc/systemd/system/spire-server.service <<'EOF'
[Unit]
Description=SPIRE Server
After=network-online.target vault.service
Wants=network-online.target

[Service]
User=spire
Group=spire
EnvironmentFile=-/opt/spire/conf/server/spire.env
ExecStart=/usr/local/bin/spire-server run -config /opt/spire/conf/server/server.conf
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
# /tmp: SPIRE creates its admin API socket at /tmp/spire-server (not PrivateTmp,
# so the CLI can reach it).
ReadWritePaths=/opt/spire/data /tmp

[Install]
WantedBy=multi-user.target
EOF

chown -R spire:spire /opt/spire
chmod 600 /opt/spire/conf/server/server.conf
systemctl daemon-reload
systemctl enable spire-server
systemctl restart spire-server

# ── 7. Vault Raft snapshot → GCS (weekly) ────────────────────────────────────
# Authenticates with the snapshot-saver AppRole (role_id from metadata, secret_id
# from /opt/vault-snapshot/secret-id placed out-of-band). Writes to a fixed key;
# the bucket keeps the last 3 versions (lifecycle rule in main.tf). The snapshot
# is Vault's barrier-encrypted data, not plaintext.
mkdir -p /opt/vault-snapshot
chmod 0700 /opt/vault-snapshot

cat > /usr/local/bin/vault-snapshot.sh <<'SNAP'
#!/usr/bin/env bash
set -euo pipefail
export PATH="/snap/bin:$PATH"   # snap-provided gcloud, absent from systemd's default PATH
md() { curl -sf -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/$1"; }
export VAULT_ADDR="https://127.0.0.1:8200" VAULT_CACERT="/opt/vault/tls/vault.crt"
ROLE_ID="$(md instance/attributes/snapshot-approle-role-id)"
BUCKET="$(md instance/attributes/snapshot-bucket)"
SECRET_ID="$(cat /opt/vault-snapshot/secret-id)"
VAULT_TOKEN="$(vault write -field=token auth/approle/login role_id="$ROLE_ID" secret_id="$SECRET_ID")"
export VAULT_TOKEN
vault operator raft snapshot save /tmp/vault.snap
gcloud storage cp /tmp/vault.snap "gs://$BUCKET/vault.snap"
rm -f /tmp/vault.snap

# SPIRE server state: a transaction-consistent sqlite copy (never a raw cp of a
# live DB) plus the disk KeyManager keys, so a rebuilt node restores the same
# datastore and the same viaduct.gcp CA — no re-attestation, no re-federation.
spdir="$(mktemp -d)"
sqlite3 /opt/spire/data/server/datastore.sqlite3 ".backup '$spdir/datastore.sqlite3'"
cp -a /opt/spire/data/server/keys.json "$spdir/keys.json"
tar -C "$spdir" -czf "$spdir/spire-data.tar.gz" datastore.sqlite3 keys.json
# keys.json holds the viaduct.gcp CA private keys. Uploaded in the clear, anyone who
# can read the snapshot bucket obtains the CA and can mint SVIDs for the whole trust
# domain. Encrypt with the KMS key the instance already holds encrypt/decrypt on, so
# bucket read alone is no longer sufficient.
KMS_REGION="$(md instance/attributes/region)"
KMS_KEYRING="$(md instance/attributes/kms-keyring)"
KMS_CRYPTOKEY="$(md instance/attributes/kms-cryptokey)"
gcloud kms encrypt \
  --location "$KMS_REGION" --keyring "$KMS_KEYRING" --key "$KMS_CRYPTOKEY" \
  --plaintext-file "$spdir/spire-data.tar.gz" \
  --ciphertext-file "$spdir/spire-data.tar.gz.enc"
gcloud storage cp "$spdir/spire-data.tar.gz.enc" "gs://$BUCKET/spire-data.tar.gz.enc"
rm -rf "$spdir"
SNAP
chmod 0755 /usr/local/bin/vault-snapshot.sh

cat > /etc/systemd/system/vault-snapshot.service <<'EOF'
[Unit]
Description=Vault Raft snapshot to GCS
After=vault.service
Wants=vault.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/vault-snapshot.sh
EOF

cat > /etc/systemd/system/vault-snapshot.timer <<'EOF'
[Unit]
Description=Weekly Vault Raft snapshot

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now vault-snapshot.timer

# ── 7b. AWS cert-role refresh ────────────────────────────────────────────────
# Refreshes the Vault aws-vault-agent cert role with the current viaduct.aws CA
# from the federated bundle store. Invoked by aws/'s federation sync over IAP
# after an AWS rebuild (a fresh datastore mints a new CA, so the pinned CA in the
# role goes stale and AWS workloads can no longer authenticate). Auths with a
# scoped AppRole that may only update this one cert path; secret-id placed
# out-of-band like the others. Also usable on a timer for the 168h rotation case.
mkdir -p /opt/vault-certrole
chmod 0700 /opt/vault-certrole

cat > /usr/local/bin/refresh-aws-certrole.sh <<'CERTROLE'
#!/usr/bin/env bash
set -euo pipefail
md() { curl -sf -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/$1"; }
export VAULT_ADDR="https://127.0.0.1:8200" VAULT_CACERT="/opt/vault/tls/vault.crt"
TD="${1:-viaduct.aws}"

# Whatever this resolves to becomes a Vault client CA for the aws-workload policy, and
# TD itself lands in allowed_uri_sans. Constrain it to the two federated domains rather
# than accepting any caller-supplied name.
case "$TD" in
  viaduct.aws|viaduct.gcp) ;;
  *)
    echo "ERROR: refusing to refresh a cert role for unexpected trust domain '${TD}'" >&2
    echo "       Expected one of: viaduct.aws, viaduct.gcp" >&2
    exit 1
    ;;
esac

ROLE_ID="$(md instance/attributes/aws-certrole-approle-role-id)"
SECRET_ID="$(cat /opt/vault-certrole/secret-id)"

ca="$(mktemp)"; trap 'rm -f "$ca"' EXIT
spire-server bundle list -id "spiffe://${TD}" -format pem > "$ca"
[ -s "$ca" ] || { echo "ERROR: empty ${TD} bundle in the SPIRE store" >&2; exit 1; }
# Non-empty is not enough: this is about to become an accepted client CA, so require
# that it actually parses as a certificate.
openssl x509 -in "$ca" -noout >/dev/null 2>&1 || {
  echo "ERROR: ${TD} bundle is not a parseable PEM certificate; refusing to install it as a Vault client CA" >&2
  exit 1
}

VAULT_TOKEN="$(vault write -field=token auth/approle/login role_id="$ROLE_ID" secret_id="$SECRET_ID")"
export VAULT_TOKEN
vault write auth/cert/certs/aws-vault-agent \
  certificate=@"$ca" display_name=aws-vault-agent policies=aws-workload \
  allowed_uri_sans="spiffe://${TD}/vault-agent" token_ttl=20m token_max_ttl=1h
echo "OK: aws-vault-agent cert role refreshed with the current ${TD} CA"
CERTROLE
chmod 0755 /usr/local/bin/refresh-aws-certrole.sh

# ── 8. WireGuard hub (private mesh overlay) ───────────────────────────────────
# This node is the mesh hub: it listens on WG_PORT and Hetzner/AWS/the operator
# dial in (spokes need no inbound port). The hub key is DURABLE in Vault
# (kv/wireguard/hub): generated once on the first bootstrapped boot, then fetched
# on every boot into a tmpfs credential (/run), so the hub PUBLIC key is stable
# across rebuilds (spokes never have to re-learn it) and the private key never
# touches the persistent disk. ip_forward lets the hub route spoke-to-spoke
# traffic. Peers are added later by the mesh distribution step.
apt-get install -y wireguard-tools sqlite3 iptables

WG_ADDR="${WG_HUB_MESH_IP}/24"                  # hub address on the 10.99.0.0/24 mesh (defined once at top)
WG_PORT="$(md instance/attributes/wg-port)"
WG_RUN_KEY="/run/wireguard/wg0.key"             # tmpfs (RAM); cleared on reboot, rewritten each boot
mkdir -p /etc/wireguard && chmod 0700 /etc/wireguard
install -d -m 0700 /run/wireguard

# Peer reconcile: the hub derives its WireGuard peers from the Vault registry
# (kv/wireguard/peers/*), each entry a spoke's {public_key, mesh_ip, psk}. Run at
# boot (after wg0 is up, so a hub rebuild re-adds every registered spoke) and on
# demand by a spoke's provisioner right after it registers (so a spoke joins
# without waiting for a hub reboot). Idempotent: `wg set` upserts each peer. The
# PSK is passed via a process-substitution fd, never written to disk.
cat > /usr/local/bin/wg-sync-peers.sh <<'SYNC'
#!/usr/bin/env bash
set -euo pipefail
export VAULT_ADDR="https://127.0.0.1:8200" VAULT_CACERT="/opt/vault/tls/vault.crt"
VAULT_TOKEN="$(vault login -method=gcp -token-only role=wireguard-hub type=gce)"; export VAULT_TOKEN
names="$(vault kv list -format=json kv/wireguard/peers 2>/dev/null | jq -r '.[]?' || true)"
for name in $names; do
  json="$(vault kv get -format=json "kv/wireguard/peers/$name" 2>/dev/null || true)"
  [ -n "$json" ] || continue
  pub="$(printf '%s' "$json" | jq -r '.data.data.public_key // empty')"
  ip="$(printf '%s' "$json"  | jq -r '.data.data.mesh_ip // empty')"
  psk="$(printf '%s' "$json" | jq -r '.data.data.psk // empty')"
  [ -n "$pub" ] && [ -n "$ip" ] || continue
  if [ -n "$psk" ]; then
    wg set wg0 peer "$pub" preshared-key <(printf '%s' "$psk") allowed-ips "$ip/32"
  else
    wg set wg0 peer "$pub" allowed-ips "$ip/32"
  fi
done
unset VAULT_TOKEN
SYNC
chmod 0755 /usr/local/bin/wg-sync-peers.sh

# Register a spoke in the mesh registry, apply it to the running hub, and echo
# back what the spoke needs. Called by a spoke's provisioner over IAP.
#   args:   <name> <public_key> <mesh_ip>
#   stdout: "hub_public_key <key>" then "psk <value>"
# Idempotent: an existing peer keeps its PSK across re-provisions.
cat > /usr/local/bin/wg-register-peer.sh <<'REG'
#!/usr/bin/env bash
set -euo pipefail
name="${1:?peer name required}"; pub="${2:?public key required}"; ip="${3:?mesh ip required}"
case "$name" in *[!a-z0-9-]*) echo "invalid peer name: $name" >&2; exit 1 ;; esac
export VAULT_ADDR="https://127.0.0.1:8200" VAULT_CACERT="/opt/vault/tls/vault.crt"
VAULT_TOKEN="$(vault login -method=gcp -token-only role=wireguard-hub type=gce)"; export VAULT_TOKEN
psk="$(vault kv get -field=psk "kv/wireguard/peers/$name" 2>/dev/null || true)"
[ -n "$psk" ] || psk="$(wg genpsk)"
vault kv put "kv/wireguard/peers/$name" public_key="$pub" mesh_ip="$ip" psk="$psk" >/dev/null
hub_pub="$(vault kv get -field=public_key kv/wireguard/hub)"
unset VAULT_TOKEN
/usr/local/bin/wg-sync-peers.sh   # apply to the running hub now, no wait for a reboot
printf 'hub_public_key %s\npsk %s\n' "$hub_pub" "$psk"
REG
chmod 0755 /usr/local/bin/wg-register-peer.sh

# Fetch (or first-time generate) the hub key from Vault. Vault is local and, by
# this point in startup, unsealed (§6a restores it on a rebuild; a plain reboot
# auto-unseals via KMS). Auth is the box's own GCE identity via the scoped
# wireguard-hub gcp-auth role (no secret-id on disk), created in BOOTSTRAP.
# Guarded: on the first-ever deploy Vault is not bootstrapped yet, so the login
# fails and we defer wg0 to the next boot rather than aborting startup.
export VAULT_ADDR="https://127.0.0.1:8200" VAULT_CACERT="/opt/vault/tls/vault.crt"
WG_HUB_KEY=""
if WG_TOKEN="$(vault login -method=gcp -token-only role=wireguard-hub type=gce 2>/dev/null)"; then
  export VAULT_TOKEN="$WG_TOKEN"
  WG_HUB_KEY="$(vault kv get -field=private_key kv/wireguard/hub 2>/dev/null || true)"
  if [ -z "$WG_HUB_KEY" ]; then
    WG_HUB_KEY="$(wg genkey)"
    vault kv put kv/wireguard/hub \
      private_key="$WG_HUB_KEY" \
      public_key="$(printf '%s' "$WG_HUB_KEY" | wg pubkey)" >/dev/null
  fi
  unset VAULT_TOKEN WG_TOKEN
fi

if [ -n "$WG_HUB_KEY" ]; then
  ( umask 077; printf '%s\n' "$WG_HUB_KEY" > "$WG_RUN_KEY" )
  printf '%s' "$WG_HUB_KEY" | wg pubkey > /etc/wireguard/wg0.pub   # non-secret, for inspection
  WG_HUB_KEY=""

  # Interface only; peers are added later by the mesh distribution step. The
  # private key is loaded from tmpfs at start, never inlined into this on-disk file.
  cat > /etc/wireguard/wg0.conf <<WGCONF
[Interface]
Address = ${WG_ADDR}
ListenPort = ${WG_PORT}
PostUp = wg set %i private-key ${WG_RUN_KEY}
WGCONF
  chmod 0600 /etc/wireguard/wg0.conf

  # A reboot clears /run, so wg0 must not auto-start before startup.sh rewrites
  # the key. ConditionPathExists makes the boot-time start SKIP (not fail) while
  # the key is absent; the explicit restart below brings it up once it is placed.
  mkdir -p /etc/systemd/system/wg-quick@wg0.service.d
  cat > /etc/systemd/system/wg-quick@wg0.service.d/10-runkey.conf <<DROPIN
[Unit]
ConditionPathExists=${WG_RUN_KEY}
DROPIN

  # Hub routes spoke-to-spoke traffic over the mesh.
  echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
  sysctl -p /etc/sysctl.d/99-wireguard-forward.conf

  systemctl daemon-reload
  systemctl enable wg-quick@wg0
  systemctl restart wg-quick@wg0

  # Re-add every registered spoke from the Vault registry. Non-fatal: an empty
  # registry (no spokes yet) or a transient Vault hiccup must not abort startup,
  # since wg0 itself is already up.
  /usr/local/bin/wg-sync-peers.sh || echo "WireGuard hub: peer reconcile deferred (empty registry or Vault not ready)."

  # MSS clamp for TCP the hub FORWARDS between mesh peers (laptop or spoke to a
  # spoke). Large segments black-hole when path-MTU discovery fails across the
  # tunnel; clamping the SYN's MSS to the path MTU fixes it. Applied here (not as a
  # wg-quick PostUp) and idempotently (-C guard), so it never gates the hub's wg0
  # bringup — a broken clamp must not take the whole mesh down.
  iptables -t mangle -C FORWARD -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null \
    || iptables -t mangle -A FORWARD -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu \
    || echo "WireGuard hub: MSS clamp not applied (iptables unavailable); large forwarded segments may need PMTU."
else
  echo "WireGuard hub: Vault not bootstrapped yet (wireguard-hub role/kv absent); deferring wg0 to the next boot after BOOTSTRAP."
fi
