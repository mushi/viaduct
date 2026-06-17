#!/usr/bin/env bash
# Viaduct GCP control-plane startup script — Phase 2a: swap + Vault.
#
# Runs on every boot (GCE startup-script). Idempotent. Reads its config from
# instance metadata so this file stays plain bash (no Terraform templating).
#
# It installs and configures Vault (Raft storage, GCP KMS auto-unseal) and
# starts it SEALED + UNINITIALISED. The operator then runs `vault operator init`
# once over SSH and stores the recovery keys + root token in 1Password. Vault
# auto-unseals via KMS thereafter. SPIRE server and the snapshot timer come in
# later phases.
set -euo pipefail

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

# Vault 1.20+ requires this to be set explicitly. mlock is DISABLED: on this
# 1 GB host mlock inflated Vault's RSS to ~530 MB (Go heap arenas locked
# resident); disabling it drops RSS to ~190 MB, which fits the box. Safe because
# this host has NO swap (see startup.sh) — there is no disk for memory to swap
# to, so secrets cannot reach the disk. This is Vault's other endorsed
# configuration for disabling mlock ("where swap is disabled").
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

# Public Vault CA cert, readable by spire (UpstreamAuthority TLS verification).
install -m 0644 /opt/vault/tls/vault.crt /opt/spire/conf/server/vault-ca.crt

cat > /opt/spire/conf/server/server.conf <<EOF
server {
  bind_address          = "0.0.0.0"
  bind_port             = "8081"
  trust_domain          = "${TRUST_DOMAIN}"
  data_dir              = "/opt/spire/data/server"
  log_level             = "INFO"
  ca_ttl                = "168h"
  default_x509_svid_ttl = "1h"
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
