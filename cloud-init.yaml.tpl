#cloud-config

# Runs once on first boot. Responsibilities:
#   • Install system packages
#   • Download binaries (conduit, xray, xray-exporter, grafana-alloy)
#   • Write systemd unit files
#   • Write /usr/local/sbin/xray-setup.sh
#   • Register (but NOT start) services — the Terraform provisioner starts
#     them after uploading backup files and users.txt
#   • Touch /var/lib/cloud-init-done to signal the provisioner it can proceed

package_update: true
package_upgrade: true
packages:
  - curl
  - ca-certificates
  - unattended-upgrades
  - unzip
  - jq
  - openssl
  - nginx

write_files:

  # ── Conduit systemd unit ──────────────────────────────────────────────────
  - path: /etc/systemd/system/conduit.service
    owner: root:root
    permissions: "0644"
    content: |
      [Unit]
      Description=Psiphon Conduit Station
      Documentation=https://conduit.psiphon.ca
      After=network-online.target
      Wants=network-online.target

      [Service]
      Type=simple
      User=conduit
      Group=conduit
      WorkingDirectory=/var/lib/conduit

      ExecStart=/usr/local/bin/conduit start \
        --data-dir /var/lib/conduit/data \
        --bandwidth ${conduit_bandwidth} \
        --max-common-clients ${conduit_max_clients} \
        --metrics-addr 127.0.0.1:9090

      Restart=always
      RestartSec=10
      TimeoutStopSec=30
      CPUQuota=${conduit_cpu_quota}

      NoNewPrivileges=true
      PrivateTmp=true
      ProtectSystem=strict
      ProtectHome=true
      ReadWritePaths=/var/lib/conduit
      CapabilityBoundingSet=
      AmbientCapabilities=

      [Install]
      WantedBy=multi-user.target

  # ── Xray systemd unit ─────────────────────────────────────────────────────
  - path: /etc/systemd/system/xray.service
    owner: root:root
    permissions: "0644"
    content: |
      [Unit]
      Description=Xray VLESS+Reality Proxy
      Documentation=https://xtls.github.io
      After=network-online.target
      Wants=network-online.target

      [Service]
      Type=simple
      User=xray
      Group=xray
      ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
      Restart=always
      RestartSec=10
      TimeoutStopSec=30

      # Bind port 443 without running as root
      AmbientCapabilities=CAP_NET_BIND_SERVICE
      CapabilityBoundingSet=CAP_NET_BIND_SERVICE

      NoNewPrivileges=true
      PrivateTmp=true
      ProtectSystem=strict
      ProtectHome=true
      ReadWritePaths=/var/log/xray

      [Install]
      WantedBy=multi-user.target

  # ── xray-exporter systemd unit ────────────────────────────────────────────
  # Scrapes Xray's internal Stats API (gRPC on 127.0.0.1:8080) and exposes
  # Prometheus metrics on 127.0.0.1:9091. Also parses access.log for per-user
  # traffic stats. Localhost-only — no inbound firewall rule needed.
  - path: /etc/systemd/system/xray-exporter.service
    owner: root:root
    permissions: "0644"
    content: |
      [Unit]
      Description=Xray Prometheus Exporter
      After=xray.service
      Wants=xray.service

      [Service]
      Type=simple
      User=xray
      Group=xray
      WorkingDirectory=/var/lib/xray-exporter
      ExecStart=/usr/local/bin/xray-exporter \
        --listen 127.0.0.1:9091 \
        --xray-endpoint 127.0.0.1:8080 \
        --log-path /var/log/xray/access.log
      Restart=always
      RestartSec=10

      NoNewPrivileges=true
      PrivateTmp=true
      ProtectSystem=strict
      ProtectHome=true
      ReadWritePaths=/var/log/xray /var/lib/xray-exporter

      [Install]
      WantedBy=multi-user.target

  # ── Grafana Alloy systemd unit ────────────────────────────────────────────
  # Alloy scrapes Conduit (:9090) and xray-exporter (:9091) locally, then
  # remote-writes to Grafana Cloud over outbound HTTPS. No inbound ports.
  - path: /etc/systemd/system/alloy.service
    owner: root:root
    permissions: "0644"
    content: |
      [Unit]
      Description=Grafana Alloy (metrics agent)
      After=network-online.target conduit.service xray-exporter.service
      Wants=network-online.target

      [Service]
      Type=simple
      User=alloy
      Group=alloy
      WorkingDirectory=/var/lib/alloy
      ExecStart=/usr/local/bin/alloy run /etc/alloy/config.alloy
      Restart=always
      RestartSec=15

      NoNewPrivileges=true
      PrivateTmp=true
      ProtectSystem=strict
      ProtectHome=true
      ReadWritePaths=/var/lib/alloy

      [Install]
      WantedBy=multi-user.target

  # ── Automatic security updates ────────────────────────────────────────────
  - path: /etc/apt/apt.conf.d/20auto-upgrades
    owner: root:root
    permissions: "0644"
    content: |
      APT::Periodic::Update-Package-Lists "1";
      APT::Periodic::Unattended-Upgrade "1";
      APT::Periodic::AutocleanInterval "7";

  # ── install-xray-exporter.sh ──────────────────────────────────────────────
  # Runs during cloud-init (runcmd). Needs bash for [[ ]] and glob comparisons,
  # so it lives here as a write_files entry (with bash shebang) rather than as
  # an inline runcmd | block (which cloud-init executes via /bin/sh / dash).
  - path: /usr/local/sbin/install-xray-exporter.sh
    owner: root:root
    permissions: "0750"
    content: |
      #!/usr/bin/env bash
      set -euo pipefail

      EXPORTER_TAG="${xray_exporter_version}"
      EXPORTER_API="https://api.github.com/repos/compassvpn/xray-exporter/releases/tags/$${EXPORTER_TAG}"

      echo "Fetching xray-exporter release metadata for $${EXPORTER_TAG}..."
      RELEASE_JSON=$(curl -fsSL --compressed -H "Accept: application/vnd.github.v3+json" "$${EXPORTER_API}")

      # Find the linux amd64 binary or archive asset URL
      ASSET_URL=$(echo "$${RELEASE_JSON}" | jq -r '
        .assets[]
        | select(
            (.name | test("linux") ) and
            (.name | test("amd64") ) and
            (.name | test("windows") | not)
          )
        | .browser_download_url' | head -1)

      if [[ -z "$${ASSET_URL}" ]]; then
        echo "FATAL: could not find a linux/amd64 asset in xray-exporter $${EXPORTER_TAG} release" >&2
        echo "Available assets:" >&2
        echo "$${RELEASE_JSON}" | jq -r '.assets[].name' >&2
        exit 1
      fi

      ASSET_NAME=$(basename "$${ASSET_URL}")
      echo "Downloading $${ASSET_NAME}..."
      curl -fsSL "$${ASSET_URL}" -o "/tmp/$${ASSET_NAME}"

      # Try to find and verify a checksums file for this release
      CHECKSUMS_URL=$(echo "$${RELEASE_JSON}" | jq -r '
        .assets[]
        | select(.name | test("(?i)(checksum|sha256|hash)"))
        | .browser_download_url' | head -1)

      if [[ -n "$${CHECKSUMS_URL}" ]]; then
        echo "Verifying against published checksums..."
        curl -fsSL "$${CHECKSUMS_URL}" -o /tmp/xray-exporter-checksums.txt
        if grep -F "$${ASSET_NAME}" /tmp/xray-exporter-checksums.txt | sha256sum --check --strict -; then
          echo "xray-exporter checksum verified."
        else
          echo "FATAL: xray-exporter checksum mismatch — aborting" >&2
          exit 1
        fi
      else
        echo "WARNING: no checksums file found for xray-exporter $${EXPORTER_TAG} — skipping verification"
      fi

      # Extract or install the binary
      if [[ "$${ASSET_NAME}" == *.tar.gz ]] || [[ "$${ASSET_NAME}" == *.tgz ]]; then
        tar -xzf "/tmp/$${ASSET_NAME}" -C /tmp --wildcards --no-anchored 'xray-exporter' 2>/dev/null \
          || tar -xzf "/tmp/$${ASSET_NAME}" -C /tmp
        find /tmp -maxdepth 2 -name 'xray-exporter' -not -path "/tmp/$${ASSET_NAME}" \
          -exec mv {} /usr/local/bin/xray-exporter \;
      elif [[ "$${ASSET_NAME}" == *.zip ]]; then
        unzip -o "/tmp/$${ASSET_NAME}" -d /tmp/xray-exporter-extract/
        find /tmp/xray-exporter-extract -name 'xray-exporter' \
          -exec mv {} /usr/local/bin/xray-exporter \;
      else
        mv "/tmp/$${ASSET_NAME}" /usr/local/bin/xray-exporter
      fi

      chmod +x /usr/local/bin/xray-exporter
      rm -f "/tmp/$${ASSET_NAME}" /tmp/xray-exporter-checksums.txt
      echo "xray-exporter installed: $(/usr/local/bin/xray-exporter --version 2>/dev/null || echo 'ok')"

  # ── xray-setup.sh ─────────────────────────────────────────────────────────
  # Called by the Terraform provisioner (not cloud-init) after backups are
  # uploaded. Reads the user list from /etc/xray/users.txt (uploaded by the
  # provisioner from vless_users). See README for details.
  - path: /usr/local/sbin/xray-setup.sh
    owner: root:root
    permissions: "0750"
    content: |
      #!/usr/bin/env bash
      set -euo pipefail

      CONFIG_DIR=/etc/xray
      CONFIG_FILE=$CONFIG_DIR/config.json
      KEYPAIR_FILE=$CONFIG_DIR/keypair.env
      USERS_FILE=$CONFIG_DIR/users.txt
      CLIENTS_DIR=$CONFIG_DIR/clients
      LOG_DIR=/var/log/xray
      SNI="${vless_sni}"
      DOMAIN="${vless_domain}"
      REALITY_PORT=8443
      WS_PORT=10000

      if [[ "$${1:-}" == "--regen" ]]; then
        echo "Regenerating Xray config (preserving keypair and UUIDs)..."
        rm -f "$CONFIG_FILE"
      fi

      if [[ -f "$CONFIG_FILE" ]]; then
        echo "Config exists. Use --regen to regenerate."
        exit 0
      fi

      [[ ! -f "$USERS_FILE" ]] && { echo "ERROR: $USERS_FILE missing." >&2; exit 1; }

      mkdir -p "$CLIENTS_DIR" "$LOG_DIR"
      chown xray:xray "$LOG_DIR"
      chmod 700 "$CLIENTS_DIR"

      # ── Reality keypair ───────────────────────────────────────────────────
      if [[ ! -f "$KEYPAIR_FILE" ]]; then
        /usr/local/bin/xray x25519 > /tmp/xray-x25519.txt 2>&1
        PRIVATE_KEY=$(awk '/PrivateKey:/  {print $NF}' /tmp/xray-x25519.txt)
        PUBLIC_KEY=$(awk  '/PublicKey/    {print $NF}' /tmp/xray-x25519.txt)
        SHORT_ID=$(openssl rand -hex 8)
        rm -f /tmp/xray-x25519.txt
        if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
          echo "ERROR: failed to parse xray x25519 output — check format" >&2
          exit 1
        fi
        printf 'PRIVATE_KEY=%s\nPUBLIC_KEY=%s\nSHORT_ID=%s\n' \
          "$PRIVATE_KEY" "$PUBLIC_KEY" "$SHORT_ID" > "$KEYPAIR_FILE"
        chmod 600 "$KEYPAIR_FILE"
        echo "Generated new Reality keypair."
      else
        # shellcheck source=/dev/null
        source "$KEYPAIR_FILE"
        echo "Loaded existing Reality keypair."
        if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" || -z "$SHORT_ID" ]]; then
          echo "ERROR: $KEYPAIR_FILE is missing PRIVATE_KEY, PUBLIC_KEY, or SHORT_ID — restore from backup or delete the file to generate a fresh keypair." >&2
          exit 1
        fi
      fi

      SERVER_IP=$(curl -fsSL --max-time 5 https://api4.my-ip.io/ip.json \
                  | jq -r '.ip' 2>/dev/null || hostname -I | awk '{print $1}')

      # ── Per-user UUIDs and Xray clients JSON ─────────────────────────────
      CLIENTS_JSON_REALITY=""
      CLIENTS_JSON_WS=""
      SEPARATOR_R=""
      SEPARATOR_W=""

      while IFS= read -r USERNAME; do
        [[ -z "$USERNAME" || "$USERNAME" == \#* ]] && continue
        UUID_FILE="$CLIENTS_DIR/$${USERNAME}.uuid"

        if [[ -f "$UUID_FILE" ]]; then
          USER_UUID=$(cat "$UUID_FILE")
          echo "Reusing UUID for: $USERNAME"
        else
          USER_UUID=$(/usr/local/bin/xray uuid)
          echo "$USER_UUID" > "$UUID_FILE"
          chmod 600 "$UUID_FILE"
          echo "Generated UUID for: $USERNAME"
        fi

        CLIENTS_JSON_REALITY+="$${SEPARATOR_R}
                {
                  \"id\": \"$USER_UUID\",
                  \"email\": \"$USERNAME\",
                  \"flow\": \"xtls-rprx-vision\"
                }"
        SEPARATOR_R=","

        CLIENTS_JSON_WS+="$${SEPARATOR_W}
                {
                  \"id\": \"$USER_UUID\",
                  \"email\": \"$USERNAME\"
                }"
        SEPARATOR_W=","

        REALITY_URI="vless://$USER_UUID@$SERVER_IP:$REALITY_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI&fp=chrome&pbk=$PUBLIC_KEY&sid=$SHORT_ID&type=tcp#$USERNAME-reality"
        WS_URI="vless://$USER_UUID@$DOMAIN:443?encryption=none&security=tls&sni=$DOMAIN&type=ws&path=%2Fvless&host=$DOMAIN#$USERNAME-ws"

        cat > "$CLIENTS_DIR/$${USERNAME}.txt" <<EOF
      # ── VLESS+Reality URI for: $USERNAME ────────────────────────────────────
      # Direct connection — bypasses Cloudflare. Use OUTSIDE Iran.
      # Server: $SERVER_IP:$REALITY_PORT | SNI spoof: $SNI
      $REALITY_URI

      # ── VLESS+WebSocket URI for: $USERNAME (via Cloudflare CDN) ─────────────
      # Use FROM IRAN — connects via example.com, hides server IP behind Cloudflare.
      # Server: $DOMAIN:443 | Path: /vless
      $WS_URI
      EOF
        chmod 600 "$CLIENTS_DIR/$${USERNAME}.txt"
      done < "$USERS_FILE"

      # ── Xray server config ────────────────────────────────────────────────
      # Includes:
      #   • VLESS+Reality inbound on port 8443 (direct connections, non-Iran)
      #   • VLESS+WebSocket inbound on 127.0.0.1:10000 (nginx proxies from 443)
      #   • Stats API (gRPC) on 127.0.0.1:8080 for xray-exporter
      #   • Metrics (expvar) on 127.0.0.1:11111 for debugging
      #   • Per-user traffic stats via policy + stats blocks
      #   • Routing: block RFC-1918 to prevent pivot into private networks
      cat > "$CONFIG_FILE" <<JSON
      {
        "log": {
          "loglevel": "warning",
          "access": "/var/log/xray/access.log",
          "error":  "/var/log/xray/error.log"
        },
        "api": {
          "tag": "api",
          "services": ["StatsService"]
        },
        "stats": {},
        "policy": {
          "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } },
          "system": { "statsInboundUplink": true, "statsInboundDownlink": true }
        },
        "metrics": {
          "tag": "metrics_in"
        },
        "inbounds": [
          {
            "listen": "0.0.0.0",
            "port": $REALITY_PORT,
            "protocol": "vless",
            "tag": "vless_in",
            "settings": {
              "clients": [$CLIENTS_JSON_REALITY
              ],
              "decryption": "none"
            },
            "streamSettings": {
              "network": "tcp",
              "security": "reality",
              "realitySettings": {
                "show": false,
                "dest": "$SNI:443",
                "serverNames": ["$SNI"],
                "privateKey": "$PRIVATE_KEY",
                "shortIds": ["$SHORT_ID"]
              }
            },
            "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
          },
          {
            "listen": "127.0.0.1",
            "port": $WS_PORT,
            "protocol": "vless",
            "tag": "vless_ws_in",
            "settings": {
              "clients": [$CLIENTS_JSON_WS
              ],
              "decryption": "none"
            },
            "streamSettings": {
              "network": "ws",
              "security": "none",
              "wsSettings": { "path": "/vless" }
            },
            "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
          },
          {
            "listen": "127.0.0.1",
            "port": 8080,
            "protocol": "dokodemo-door",
            "tag": "api",
            "settings": { "address": "127.0.0.1" }
          },
          {
            "listen": "127.0.0.1",
            "port": 11111,
            "protocol": "dokodemo-door",
            "tag": "metrics_in",
            "settings": { "address": "127.0.0.1" }
          }
        ],
        "outbounds": [
          { "protocol": "freedom",   "tag": "direct" },
          { "protocol": "blackhole", "tag": "block"  }
        ],
        "routing": {
          "domainStrategy": "IPIfNonMatch",
          "rules": [
            { "type": "field", "inboundTag": ["api"],        "outboundTag": "api" },
            { "type": "field", "inboundTag": ["metrics_in"], "outboundTag": "direct" },
            { "type": "field", "ip": ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16","100.64.0.0/10","fc00::/7","::1/128"], "outboundTag": "block" }
          ]
        }
      }
      JSON

      chown root:xray "$CONFIG_FILE"
      chmod 640 "$CONFIG_FILE"

      echo ""
      echo "Xray setup complete. Client URIs:"
      ls -1 "$CLIENTS_DIR/"*.txt 2>/dev/null | while read -r f; do echo "  $f"; done || true

runcmd:
  # ── System users ──────────────────────────────────────────────────────────
  - useradd --system --no-create-home --shell /usr/sbin/nologin conduit
  - useradd --system --no-create-home --shell /usr/sbin/nologin xray
  - useradd --system --no-create-home --shell /usr/sbin/nologin alloy

  # ── Directories ───────────────────────────────────────────────────────────
  - mkdir -p /var/lib/conduit/data
  - chown -R conduit:conduit /var/lib/conduit
  - mkdir -p /etc/xray/clients
  - chmod 700 /etc/xray/clients
  - mkdir -p /var/lib/xray-exporter
  - chown xray:xray /var/lib/xray-exporter
  - mkdir -p /var/lib/alloy /etc/alloy
  - chown alloy:alloy /var/lib/alloy

  # ── Conduit binary ────────────────────────────────────────────────────────
  # Checksum pinned in variables.tf / terraform.tfvars.
  # To obtain the correct value for a new version, run: scripts/get-checksums.sh
  - |
    curl -fsSL \
      "https://github.com/Psiphon-Inc/conduit/releases/download/${conduit_version}/conduit-linux-amd64" \
      -o /tmp/conduit
    echo "${conduit_sha256}  /tmp/conduit" | sha256sum --check --strict - \
      || { echo "FATAL: conduit binary checksum mismatch — aborting"; exit 1; }
    mv /tmp/conduit /usr/local/bin/conduit
    chmod +x /usr/local/bin/conduit

  # ── Xray binary ───────────────────────────────────────────────────────────
  # Xray releases include a Xray-linux-64.zip.dgst file (SHA-512). We verify
  # both the zip against our pinned SHA-256 and then the extracted binary.
  - |
    curl -fsSL \
      "https://github.com/XTLS/Xray-core/releases/download/${xray_version}/Xray-linux-64.zip" \
      -o /tmp/xray.zip
    echo "${xray_zip_sha256}  /tmp/xray.zip" | sha256sum --check --strict - \
      || { echo "FATAL: Xray zip checksum mismatch — aborting"; exit 1; }
    unzip -o /tmp/xray.zip xray -d /usr/local/bin/
    chmod +x /usr/local/bin/xray
    rm /tmp/xray.zip

  # ── xray-exporter binary ──────────────────────────────────────────────────
  # Delegates to a write_files bash script (install-xray-exporter.sh) so that
  # bash-specific syntax ([[ ]], glob ==) runs under bash, not /bin/sh (dash).
  - /usr/local/sbin/install-xray-exporter.sh

  # ── Grafana Alloy binary ──────────────────────────────────────────────────
  # Grafana publishes SHA256SUMS alongside each release; we verify the zip
  # against our pinned value before extracting.
  - |
    curl -fsSL \
      "https://github.com/grafana/alloy/releases/download/${alloy_version}/alloy-linux-amd64.zip" \
      -o /tmp/alloy.zip
    echo "${alloy_zip_sha256}  /tmp/alloy.zip" | sha256sum --check --strict - \
      || { echo "FATAL: Grafana Alloy zip checksum mismatch — aborting"; exit 1; }
    unzip -o /tmp/alloy.zip alloy-linux-amd64 -d /tmp/
    mv /tmp/alloy-linux-amd64 /usr/local/bin/alloy
    chmod +x /usr/local/bin/alloy
    rm /tmp/alloy.zip

  # ── nginx: TLS cert + WebSocket reverse proxy config ─────────────────────
  # Generates a self-signed cert (Cloudflare SSL mode must be set to "Full").
  # nginx proxies wss://example.com/vless → xray WS inbound on 127.0.0.1:10000.
  # The default site is removed so only our config runs on port 443.
  - |
    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
      -keyout /etc/nginx/ssl/origin.key \
      -out /etc/nginx/ssl/origin.crt \
      -subj "/CN=${vless_domain}" \
      2>/dev/null
    chmod 600 /etc/nginx/ssl/origin.key
    cat > /etc/nginx/conf.d/vless-ws.conf <<'NGINX_CONF'
    server {
        listen 443 ssl default_server;
        listen [::]:443 ssl default_server;
        server_name _;

        ssl_certificate     /etc/nginx/ssl/origin.crt;
        ssl_certificate_key /etc/nginx/ssl/origin.key;
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_ciphers         HIGH:!aNULL:!MD5;

        location /vless {
            proxy_pass         http://127.0.0.1:10000;
            proxy_http_version 1.1;
            proxy_set_header   Upgrade $http_upgrade;
            proxy_set_header   Connection "upgrade";
            proxy_set_header   Host $host;
            proxy_read_timeout 86400s;
        }

        location / {
            return 404;
        }
    }
    NGINX_CONF
    rm -f /etc/nginx/sites-enabled/default
    nginx -t && systemctl reload nginx

  # ── Register units (do NOT start — provisioner does that) ─────────────────
  - systemctl daemon-reload
  - systemctl enable conduit.service xray.service xray-exporter.service alloy.service nginx.service

  # ── Signal cloud-init completion ──────────────────────────────────────────
  # Only reached if all checksum verifications above passed.
  - touch /var/lib/cloud-init-done
