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
