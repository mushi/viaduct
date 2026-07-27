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

# ── 3. TLS for the Vault listener (self-signed; SAN = the static IP) ─────────
# Agents trust this cert as their VAULT_CACERT. The static IP keeps the SAN
# stable across instance rebuilds.
mkdir -p /opt/vault/tls
if [ ! -f /opt/vault/tls/vault.crt ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout /opt/vault/tls/vault.key -out /opt/vault/tls/vault.crt -days 3650 \
    -subj "/CN=viaduct-vault" \
    -addext "subjectAltName=IP:${VAULT_IP},IP:127.0.0.1"
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
  # restored data. Mirrors RESTORE.md.
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
  if gcloud storage ls "gs://$BUCKET/spire-data.tar.gz" >/dev/null 2>&1; then
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
gcloud storage cp "$spdir/spire-data.tar.gz" "gs://$BUCKET/spire-data.tar.gz"
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
ROLE_ID="$(md instance/attributes/aws-certrole-approle-role-id)"
SECRET_ID="$(cat /opt/vault-certrole/secret-id)"

ca="$(mktemp)"; trap 'rm -f "$ca"' EXIT
spire-server bundle list -id "spiffe://${TD}" -format pem > "$ca"
[ -s "$ca" ] || { echo "ERROR: empty ${TD} bundle in the SPIRE store" >&2; exit 1; }

VAULT_TOKEN="$(vault write -field=token auth/approle/login role_id="$ROLE_ID" secret_id="$SECRET_ID")"
export VAULT_TOKEN
vault write auth/cert/certs/aws-vault-agent \
  certificate=@"$ca" display_name=aws-vault-agent policies=aws-workload \
  allowed_uri_sans="spiffe://${TD}/vault-agent" token_ttl=20m token_max_ttl=1h
echo "OK: aws-vault-agent cert role refreshed with the current ${TD} CA"
CERTROLE
chmod 0755 /usr/local/bin/refresh-aws-certrole.sh

# ── 8. WireGuard hub (private mesh overlay) ───────────────────────────────────
# This node is the mesh hub: it listens on WG_PORT and Hetzner/AWS/the admin
# laptop dial in (spokes need no inbound port). The node's private key is
# generated once at first boot and sealed to the vTPM via systemd-creds — the
# plaintext key only transits a pipe and never lands on disk. Peers are added
# later by the provisioner. ip_forward lets the hub route spoke-to-spoke traffic.
apt-get install -y wireguard-tools sqlite3

# TSS userspace libraries that systemd-creds dlopens to seal the WG key to the
# vTPM (esys, rc, mu, and the device TCTI for /dev/tpmrm0). The image ships the
# vTPM device + kernel driver but NOT these libs, so without them
# `systemd-creds --with-key=tpm2` fails "Operation not supported" and, under
# `set -e`, aborts the whole startup script. The sonamed names can drift across
# Ubuntu releases, so fall back to tpm2-tools (which depends on the right runtime)
# rather than let a future image silently reintroduce that abort.
apt-get install -y libtss2-esys-3.0.2-0 libtss2-rc0 libtss2-mu-4.0.1-0 libtss2-tcti-device0 \
  || apt-get install -y tpm2-tools

WG_ADDR="10.99.0.1/24"                        # hub address on the 10.99.0.0/24 mesh
WG_PORT="$(md instance/attributes/wg-port)"
mkdir -p /etc/wireguard && chmod 0700 /etc/wireguard

# Generate + TPM-seal the private key once. tee fans the freshly-generated key to
# `wg pubkey` (public key, non-secret) and to systemd-creds (TPM-sealed blob);
# the raw private key is never written to disk.
if [ ! -f /etc/wireguard/wg0.key.cred ]; then
  ( umask 077
    wg genkey | tee >(wg pubkey > /etc/wireguard/wg0.pub) \
      | systemd-creds encrypt --name=wg0-privkey --with-key=tpm2 - /etc/wireguard/wg0.key.cred )
fi

# Interface only: no PrivateKey inline (injected at start from the sealed
# credential) and no peers yet (the provisioner adds them).
cat > /etc/wireguard/wg0.conf <<WGCONF
[Interface]
Address = ${WG_ADDR}
ListenPort = ${WG_PORT}
PostUp = wg set %i private-key "\$CREDENTIALS_DIRECTORY/wg0-privkey"
WGCONF
chmod 0600 /etc/wireguard/wg0.conf

# Drop-in: decrypt the sealed key into the service's runtime credential store
# (RAM, service-scoped), so PostUp can load it without it ever touching disk.
mkdir -p /etc/systemd/system/wg-quick@wg0.service.d
cat > /etc/systemd/system/wg-quick@wg0.service.d/10-credential.conf <<'DROPIN'
[Service]
LoadCredentialEncrypted=wg0-privkey:/etc/wireguard/wg0.key.cred
DROPIN

# Hub routes spoke-to-spoke traffic over the mesh.
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
sysctl -p /etc/sysctl.d/99-wireguard-forward.conf

systemctl daemon-reload
systemctl enable --now wg-quick@wg0
