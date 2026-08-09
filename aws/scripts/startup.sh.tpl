#!/usr/bin/env bash
# aws/startup.sh.tpl — Terraform renders this (templatefile) into the AWS node's
# user_data; runs ONCE at instance creation. One-phase, self-contained:
#   SPIRE server (KMS-rooted trust domain viaduct.aws, federated with viaduct.gcp)
#   SPIRE agent (aws_iid; unix + k8s WorkloadAttestors)
#   k3s + workloads (CSI driver, Conduit, Alloy)
#   egress guardrail (auto-stop near the free-tier cap)
# Cross-cloud steps (federation bundle, vault.crt, Alloy) run as a retrying unit,
# self-healing once the GCP control plane is reachable.
#
# Vendored files/manifests are injected as dollar-brace vars into
# single-quoted heredocs.
set -euo pipefail
exec > >(tee -a /var/log/viaduct-startup.log) 2>&1
log() { echo "[viaduct-startup] $(date -u +%H:%M:%S) $*"; }

# ─── Terraform-injected values (the only templatefile tokens in this script) ──
REGION="${region}"
# GCP_IP is the hub's MESH address (10.99.0.1): SPIRE federation (:8443), the Vault
# CA fetch (:8200) and Alloy's cross-cloud Vault auth all ride wg0, not the public
# IP. The WG endpoint itself dials the public IP — that lives in wg-mesh-join.sh,
# not here. First-boot federation retries until this node's mesh is up (post-boot
# provisioner), then converges.
GCP_IP="${wg_hub_ip}"
TRUST_DOMAIN="${trust_domain}"
GCP_TRUST_DOMAIN="${gcp_trust_domain}"
SPIRE_VERSION="${spire_version}"
SPIRE_SHA256="${spire_sha256}"
K3S_VERSION="${k3s_version}"
KUBECTL="k3s kubectl"
NODE_NAME="$(hostname)"

log "starting Viaduct AWS node provisioning (region=$REGION, trust_domain=$TRUST_DOMAIN)"

# ─── 1. base packages ─────────────────────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl unzip ca-certificates openssl >/dev/null

# ─── 2. SPIRE (server + agent, arm64 musl, checksum-pinned) ───────────────────
install -d /opt/spire/bin /opt/spire/conf/server /opt/spire/conf/agent /opt/spire/data/server /opt/spire/data/agent
curl -fsSL -o /tmp/spire.tgz "https://github.com/spiffe/spire/releases/download/v$SPIRE_VERSION/spire-$SPIRE_VERSION-linux-arm64-musl.tar.gz"
echo "$SPIRE_SHA256  /tmp/spire.tgz" | sha256sum -c -
tar -xzf /tmp/spire.tgz -C /tmp
install -m0755 "/tmp/spire-$SPIRE_VERSION/bin/spire-server" /opt/spire/bin/spire-server
install -m0755 "/tmp/spire-$SPIRE_VERSION/bin/spire-agent"  /opt/spire/bin/spire-agent
ln -sf /opt/spire/bin/spire-server /usr/local/bin/spire-server
ln -sf /opt/spire/bin/spire-agent  /usr/local/bin/spire-agent
rm -rf /tmp/spire.tgz "/tmp/spire-$SPIRE_VERSION"

# ─── 3. SPIRE server: KMS-rooted self-signed CA + aws_iid + federation ────────
cat > /opt/spire/conf/server/server.conf <<EOF
server {
  bind_address          = "127.0.0.1"
  bind_port             = "8081"
  trust_domain          = "$TRUST_DOMAIN"
  data_dir              = "/opt/spire/data/server"
  log_level             = "INFO"
  ca_ttl                = "168h"
  default_x509_svid_ttl = "1h"
  disable_jwt_svids     = true

  federation {
    bundle_endpoint {
      address = "0.0.0.0"
      port    = 8443
    }
    federates_with "$GCP_TRUST_DOMAIN" {
      bundle_endpoint_url = "https://$GCP_IP:8443"
      bundle_endpoint_profile "https_spiffe" {
        endpoint_spiffe_id = "spiffe://$GCP_TRUST_DOMAIN/spire/server"
      }
    }
  }
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type     = "sqlite3"
      connection_string = "/opt/spire/data/server/datastore.sqlite3"
    }
  }
  KeyManager "aws_kms" {
    plugin_data {
      region               = "$REGION"
      key_identifier_value = "viaduct-aws"
    }
  }
  NodeAttestor "aws_iid" {
    plugin_data {}
  }
}
EOF

cat > /etc/systemd/system/spire-server.service <<'EOF'
[Unit]
Description=SPIRE Server (viaduct.aws)
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/opt/spire/bin/spire-server run -config /opt/spire/conf/server/server.conf
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now spire-server
log "waiting for SPIRE server..."
for i in $(seq 1 30); do spire-server bundle show >/dev/null 2>&1 && break; sleep 2; done

# ─── 4. k3s (pinned; trimmed for the small box) ───────────────────────────────
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="$K3S_VERSION" \
  INSTALL_K3S_EXEC="server --disable traefik --disable servicelb" sh -
log "waiting for k3s node Ready..."
for i in $(seq 1 60); do $KUBECTL get nodes 2>/dev/null | grep -q ' Ready ' && break; sleep 5; done

# ─── 5. write k8s manifests + the namespaces/RBAC (creates the agent SA token) ─
install -d /opt/viaduct/k8s
cat > /opt/viaduct/k8s/00-namespaces-rbac.yaml <<'K8S_RBAC'
${k8s_rbac}
K8S_RBAC
cat > /opt/viaduct/k8s/01-spiffe-csi-driver.yaml <<'K8S_CSI'
${k8s_csi}
K8S_CSI
cat > /opt/viaduct/k8s/10-conduit.yaml <<'K8S_CONDUIT'
${k8s_conduit}
K8S_CONDUIT
cat > /opt/viaduct/k8s/20-alloy.yaml <<'K8S_ALLOY'
${k8s_alloy}
K8S_ALLOY
# substitute the GCP control-plane IP (kept as a placeholder in the public repo)
sed -i "s|__GCP_CONTROL_PLANE_IP__|$GCP_IP|g" /opt/viaduct/k8s/20-alloy.yaml
$KUBECTL apply -f /opt/viaduct/k8s/00-namespaces-rbac.yaml

# ─── 6. SPIRE agent: aws_iid + unix + k8s (kubelet via a rotated SA token) ────
spire-server bundle show > /opt/spire/conf/agent/bootstrap.crt

# Short-lived, rotated kubelet SA token for the k8s WorkloadAttestor — no standing
# Secret. A oneshot mints a 24h token (kubectl create token, via the node's k3s
# admin kubeconfig) and atomically rewrites the 0600-root token file; a timer
# rotates it every 12h, well inside the 24h TTL. The agent's k8s attestor uses the
# secure kubelet client, which re-reads token_path on its reload_interval (~1m), so
# a rotated file is picked up with no agent restart and no attestation gap.
install -m0755 /dev/stdin /usr/local/sbin/spire-agent-token.sh <<'MINT'
#!/usr/bin/env bash
set -euo pipefail
DEST=/opt/spire/conf/agent/k8s-sa-token
for i in $(seq 1 10); do
  if TOKEN=$(/usr/local/bin/k3s kubectl create token spire-agent -n spire --duration=24h 2>/dev/null) && [ -n "$TOKEN" ]; then
    umask 077
    tmp=$(mktemp "$DEST.XXXXXX")
    printf '%s' "$TOKEN" > "$tmp"
    mv -f "$tmp" "$DEST"   # atomic swap; the attestor never reads a half-written file
    exit 0
  fi
  sleep 3
done
echo "spire-agent-token: failed to mint SA token" >&2
exit 1
MINT
cat > /etc/systemd/system/spire-agent-token.service <<'EOF'
[Unit]
Description=Mint + rotate the SPIRE agent's k8s WorkloadAttestor SA token
After=k3s.service
Wants=k3s.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/spire-agent-token.sh
EOF
cat > /etc/systemd/system/spire-agent-token.timer <<'EOF'
[Unit]
Description=Rotate the SPIRE agent k8s SA token (well inside its 24h TTL)
[Timer]
# Re-mint shortly after boot — the root disk survives stop/start, so a persisted
# token could be expired on restart and would block k8s attestation until the next
# rotation — then every 12h thereafter.
OnBootSec=1min
OnUnitActiveSec=12h
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl start spire-agent-token.service   # initial mint, before the agent starts
systemctl enable --now spire-agent-token.timer

cat > /opt/spire/conf/agent/agent.conf <<EOF
agent {
  data_dir          = "/opt/spire/data/agent"
  log_level         = "INFO"
  server_address    = "127.0.0.1"
  server_port       = "8081"
  trust_domain      = "$TRUST_DOMAIN"
  trust_bundle_path = "/opt/spire/conf/agent/bootstrap.crt"
  socket_path       = "/run/spire-agent/public/api.sock"
}
plugins {
  NodeAttestor "aws_iid" { plugin_data {} }
  KeyManager "disk" { plugin_data { directory = "/opt/spire/data/agent" } }
  WorkloadAttestor "unix" { plugin_data {} }
  WorkloadAttestor "k8s" {
    plugin_data {
      skip_kubelet_verification = true
      token_path                = "/opt/spire/conf/agent/k8s-sa-token"
      node_name                 = "$NODE_NAME"
    }
  }
}
EOF

cat > /etc/systemd/system/spire-agent.service <<'EOF'
[Unit]
Description=SPIRE Agent (viaduct.aws, aws_iid)
After=spire-server.service spire-agent-token.service network-online.target
# Pull a fresh token mint before the agent on every boot (weak dep: if k3s/mint is
# slow the agent still starts and picks up the token on the timer + next reload).
Wants=network-online.target spire-agent-token.service
[Service]
RuntimeDirectory=spire-agent
ExecStart=/opt/spire/bin/spire-agent run -config /opt/spire/conf/agent/agent.conf
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now spire-agent
log "waiting for SPIRE agent to attest..."
for i in $(seq 1 30); do spire-server agent list 2>/dev/null | grep -q aws_iid && break; sleep 2; done

# ─── 7. CSI driver + Conduit (no cross-cloud deps) ────────────────────────────
$KUBECTL apply -f /opt/viaduct/k8s/01-spiffe-csi-driver.yaml
$KUBECTL apply -f /opt/viaduct/k8s/10-conduit.yaml

# ─── 8. workload registration entry (parent = this agent's runtime aws_iid id) ─
AGENT_ID=$(spire-server agent list | awk '/SPIFFE ID/{print $4}' | grep aws_iid | head -1)
if [ -n "$AGENT_ID" ]; then
  spire-server entry create \
    -parentID "$AGENT_ID" \
    -spiffeID "spiffe://$TRUST_DOMAIN/vault-agent" \
    -selector k8s:ns:viaduct -selector k8s:sa:vault-agent \
    -dns vault-agent.aws || true
fi

# ─── 9. aws-cli v2 + egress guardrail (auto-stop near free-tier cap) ──────────
curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-aarch64.zip" -o /tmp/awscliv2.zip
( cd /tmp && unzip -q -o awscliv2.zip && ./aws/install --update ); rm -rf /tmp/awscliv2.zip /tmp/aws
install -m0755 /dev/stdin /usr/local/sbin/egress-guardrail.sh <<'GUARDRAIL'
${guardrail_script}
GUARDRAIL
cat > /etc/systemd/system/egress-guardrail.service <<'EOF'
[Unit]
Description=Conduit egress guardrail (stop instance near free-tier cap)
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/egress-guardrail.sh
EOF
cat > /etc/systemd/system/egress-guardrail.timer <<'EOF'
[Unit]
Description=Run egress guardrail every 15 min
[Timer]
OnCalendar=*:0/15
Persistent=true
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now egress-guardrail.timer

# ─── 10. cross-cloud bootstrap (self-driving; retries for the mesh) ────────────
# Imports the viaduct.gcp federation bundle and deploys Alloy. It needs the mesh, which
# the AWS-root provisioner (wg-mesh-join) brings up post-boot, so the unit auto-starts at
# boot and its own retry loop waits until the mesh + GCP are reachable. No fingerprint is
# synced: the mesh authenticates the peer, so Alloy TOFUs GCP Vault's cert per pod start,
# self-healing across a GCP cert rotation with no refresh step.
cat > /opt/viaduct/crosscloud.env <<EOF
GCP_IP=$GCP_IP
GCP_TRUST_DOMAIN=$GCP_TRUST_DOMAIN
EOF
install -d -m0755 /opt/viaduct/lib
install -m0644 /dev/stdin /opt/viaduct/lib/mesh-trust.sh <<'MESHTRUST'
${mesh_trust_lib}
MESHTRUST
install -m0755 /dev/stdin /opt/viaduct/crosscloud-bootstrap.sh <<'CROSSCLOUD'
${crosscloud_script}
CROSSCLOUD
cat > /etc/systemd/system/viaduct-crosscloud.service <<'EOF'
[Unit]
Description=Viaduct cross-cloud bootstrap (federation bundle + Alloy)
After=spire-agent.service k3s.service wg-quick@wg0.service network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/opt/viaduct/crosscloud-bootstrap.sh
RemainAfterExit=true
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
# enable = auto-start on future boots (After=wg-quick@wg0, so the mesh is up first).
# start --no-block = kick it off now without waiting on its retry loop, which would block
# cloud-init; it retries in the background until the mesh (wg-mesh-join, post-boot) is up.
systemctl enable viaduct-crosscloud.service
systemctl start --no-block viaduct-crosscloud.service

# ─── 11. WireGuard spoke key (mesh member; provisioner finalises wg0) ──────────
# Generate this node's WG key on first boot, 0600 on the persistent disk. The
# arm64 AMI exposes no NitroTPM, so there is no vTPM to seal to; this matches how
# the other spoke (Hetzner) holds its key. The provisioner writes wg0.conf with
# the hub peer over SSM and starts wg-quick; on a reboot the enabled unit reads
# the persisted conf + key. A rebuild regenerates the key, and the provisioner
# re-registers the new public key with the hub.
apt-get install -y -qq wireguard-tools >/dev/null
install -d -m 0700 /etc/wireguard
if [ ! -f /etc/wireguard/wg0.key ]; then
  ( umask 077; wg genkey > /etc/wireguard/wg0.key )
  wg pubkey < /etc/wireguard/wg0.key > /etc/wireguard/wg0.pub
fi

log "Viaduct AWS node provisioning complete (cross-cloud bootstrap runs in background)."
