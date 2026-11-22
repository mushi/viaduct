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
packages:
  - curl
  - ca-certificates
  - unattended-upgrades
  - unzip
  - jq
  - openssl
  - nginx
  - certbot
  - python3-certbot-dns-cloudflare

# ── Login users: deploy (automation) + ops (interactive, least-privilege) ────
# Root SSH login is disabled (sshd drop-in below); admin is via these two only.
users:
  - default
  - name: deploy
    shell: /bin/bash
    ssh_authorized_keys:
      - ${ssh_public_key}
    # Provisioning needs near-root power (writes system configs, restarts
    # services) — honestly root-equivalent. The gain over root SSH is a named,
    # audited identity + no root login exposed, not a privilege boundary.
    sudo: "ALL=(ALL) NOPASSWD:ALL"
  - name: ops
    shell: /bin/bash
    ssh_authorized_keys:
      - ${ops_ssh_public_key}
    # Genuine least-privilege for interactive debugging: inspect + service
    # lifecycle only, no file writes (systemctl fixed to status/restart/reload).
    # journalctl is reached only through a wrapper: a sudo wildcard matches the
    # entire remaining argument string, so `journalctl *` also granted
    # --vacuum-time, which destroys the audit record. The wildcard below is on the
    # wrapper, which validates its own input — that is where the boundary lives.
    sudo: "ALL=(root) NOPASSWD: /usr/bin/systemctl status *, /usr/bin/systemctl restart *, /usr/bin/systemctl reload *, /usr/local/bin/ops-journal, /usr/local/bin/ops-journal *"

write_files:

  # ── SSH hardening: no root login, key-only, restrict to deploy + ops ───────
  - path: /etc/ssh/sshd_config.d/10-hardening.conf
    owner: root:root
    permissions: "0644"
    content: |
      PermitRootLogin no
      PasswordAuthentication no
      AllowUsers deploy ops

  # ── ops journal wrapper ───────────────────────────────────────────────────
  # The only way ops reaches journalctl. It accepts no pass-through arguments,
  # only a unit from the allowlist and a keyword it resolves to a fixed command.
  - path: /usr/local/bin/ops-journal
    owner: root:root
    permissions: "0755"
    content: |
      #!/bin/bash
      # Read-only journal access for the units this node actually runs. The unit
      # name is matched against the allowlist and the *matched literal* is what
      # journalctl receives, so nothing the caller typed is ever passed through.
      set -euo pipefail

      ALLOWED="conduit xray xray-probe-client xray-exporter xray-user-stats probe alloy nginx ssh"

      usage() {
        echo "usage: sudo ops-journal <unit> [follow]" >&2
        echo "units: $ALLOWED" >&2
        exit 64
      }

      [ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage

      unit=""
      for u in $ALLOWED; do
        if [ "$u" = "$1" ]; then unit="$u"; break; fi
      done
      [ -n "$unit" ] || { echo "ops-journal: '$1' is not an inspectable unit" >&2; usage; }

      case "$${2:-}" in
        "")     exec /usr/bin/journalctl --no-pager -n 500 -u "$unit" ;;
        follow) exec /usr/bin/journalctl --no-pager -n 100 -f -u "$unit" ;;
        *)      usage ;;
      esac

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

  # ── Xray probe SOCKS-client systemd unit ─────────────────────────────────────────
  - path: /etc/systemd/system/xray-probe-client.service
    owner: root:root
    permissions: "0644"
    content: |
      [Unit]
      Description=Xray VLESS/Reality client — SOCKS proxy for the availability probe
      Documentation=https://xtls.github.io
      After=network-online.target xray.service
      Wants=network-online.target

      [Service]
      Type=simple
      User=xray
      Group=xray
      ExecStart=/usr/local/bin/xray run -config /etc/xray/probe-client.json
      Restart=always
      RestartSec=10
      TimeoutStopSec=30

      # Drop all caps
      CapabilityBoundingSet=

      NoNewPrivileges=true
      PrivateTmp=true
      ProtectSystem=strict
      ProtectHome=true

      [Install]
      WantedBy=multi-user.target

  # ── Xray probe systemd unit ─────────────────────────────────────────────────────
  - path: /etc/systemd/system/probe.service
    owner: root:root
    permissions: "0644"
    content: |
      [Unit]
      Description=Xray VLESS/Reality availability probe — exposes :9110/metrics
      Documentation=https://github.com/mushi/viaduct/tree/main/probe
      After=network-online.target xray-probe-client.service
      Wants=network-online.target

      [Service]
      Type=simple
      User=probe
      Group=probe
      ExecStart=/usr/local/bin/probe
      Restart=always
      RestartSec=10
      TimeoutStopSec=30

      # Drop all caps
      CapabilityBoundingSet=

      NoNewPrivileges=true
      PrivateTmp=true
      ProtectSystem=strict
      ProtectHome=true

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
        --log-path /var/log/xray/access.log \
        --log-time-window 1440
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

  # ── xray-user-stats: per-user traffic exporter ───────────────────────────
  # xray-exporter intentionally skips user-level stats from the Stats API
  # (cardinality guard). This sidecar queries the Stats API directly and
  # exposes cumulative per-user uplink/downlink bytes on :9092/metrics.
  - path: /usr/local/bin/xray-user-stats.py
    owner: root:root
    permissions: "0755"
    content: |
      #!/usr/bin/env python3
      """Prometheus exporter: per-user traffic bytes from xray Stats API."""
      import json, subprocess
      from http.server import HTTPServer, BaseHTTPRequestHandler

      LISTEN  = ("127.0.0.1", 9092)
      XRAY    = "127.0.0.1:8080"
      BINARY  = "/usr/local/bin/xray"

      def query_stats():
          try:
              r = subprocess.run(
                  [BINARY, "api", "statsquery", f"--server={XRAY}", "--pattern=user"],
                  capture_output=True, text=True, timeout=5,
              )
              return json.loads(r.stdout).get("stat", [])
          except Exception:
              return []

      def render(stats):
          up, down = {}, {}
          for s in stats:
              parts = s.get("name", "").split(">>>")
              if len(parts) != 4 or parts[0] != "user" or parts[2] != "traffic":
                  continue
              user, direction, value = parts[1], parts[3], s.get("value", 0)
              (up if direction == "uplink" else down)[user] = value
          lines = [
              "# HELP xray_user_uplink_bytes_total Cumulative uplink bytes per user",
              "# TYPE xray_user_uplink_bytes_total counter",
          ]
          for user, v in up.items():
              lines.append(f'xray_user_uplink_bytes_total{{user="{user}"}} {v}')
          lines += [
              "# HELP xray_user_downlink_bytes_total Cumulative downlink bytes per user",
              "# TYPE xray_user_downlink_bytes_total counter",
          ]
          for user, v in down.items():
              lines.append(f'xray_user_downlink_bytes_total{{user="{user}"}} {v}')
          return "\n".join(lines) + "\n"

      class Handler(BaseHTTPRequestHandler):
          def do_GET(self):
              body = render(query_stats()).encode()
              self.send_response(200)
              self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
              self.send_header("Content-Length", str(len(body)))
              self.end_headers()
              self.wfile.write(body)
          def log_message(self, *_):
              pass

      HTTPServer(LISTEN, Handler).serve_forever()

  - path: /etc/systemd/system/xray-user-stats.service
    owner: root:root
    permissions: "0644"
    content: |
      [Unit]
      Description=Xray per-user traffic Prometheus exporter
      After=xray.service
      Wants=xray.service

      [Service]
      Type=simple
      User=xray
      Group=xray
      ExecStart=/usr/bin/python3 /usr/local/bin/xray-user-stats.py
      Restart=always
      RestartSec=10

      NoNewPrivileges=true
      PrivateTmp=true
      ProtectSystem=strict
      ProtectHome=true

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

  # ── Ubuntu baseline ───────────────────────────────────────────────────────
  # Sourced by the first runcmd step. POSIX sh: cloud-init runs runcmd under dash.
  # Each piece exists because Ubuntu 26.04 broke the boot without it:
  #   - the Rust coreutils (uutils) are the default, and these scripts were written
  #     against GNU behaviour (sha256sum --check --strict on every pin, stat, base64);
  #   - a kernel fix arrives as a new package, which plain `apt-get upgrade` holds back;
  #   - nothing reboots the node into an installed kernel fix.
  - path: /usr/local/lib/viaduct/os-baseline.sh
    owner: root:root
    permissions: "0644"
    content: |
      # Every apt call waits for the dpkg lock: apt-daily and unattended-upgrades hold it at boot.
      osb_apt() {
        DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 -y -q "$@"
      }

      # Swap to GNU coreutils and fail if the swap did not take. apt counts
      # coreutils-from-uutils as essential, so the removal is named and allowed;
      # coreutils stays provided because the GNU variant lands in the same transaction.
      osb_gnu_coreutils() {
        dpkg-query -W -f='$${Status}' coreutils-from-gnu 2>/dev/null | grep -q 'install ok installed' \
          || osb_apt --allow-remove-essential install coreutils-from-gnu coreutils-from-uutils- >/dev/null \
          || return 1
        ls --version | head -n 1 | grep -q 'GNU coreutils' && return 0
        echo "FATAL - GNU coreutils not active (coreutils-from-gnu)" >&2
        return 1
      }

      # Security and kernel updates. --with-new-pkgs installs new dependencies (a new
      # kernel is linux-image-<version>) but never removes anything.
      osb_security_upgrade() {
        osb_apt upgrade --with-new-pkgs
      }

      # A kernel fix only takes effect after a reboot, and nothing else reboots this node.
      # Reboot in the quiet hours when an update requires it, even with a session open.
      osb_auto_reboot() {
        cat > /etc/apt/apt.conf.d/52viaduct-auto-reboot <<'APTREBOOT'
      Unattended-Upgrade::Automatic-Reboot "true";
      Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
      Unattended-Upgrade::Automatic-Reboot-Time "03:30";
      APTREBOOT
      }

      # In order: package lists, GNU coreutils (before anything relies on them),
      # updates, reboot policy.
      osb_baseline() {
        osb_apt update && osb_gnu_coreutils && osb_security_upgrade && osb_auto_reboot
      }

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

      # Verify against the pinned SHA-256. This release publishes no checksums
      # file, so xray-exporter is pinned in terraform.tfvars (scripts/get-checksums.sh),
      # exactly like conduit/xray/alloy.
      EXPECTED_SHA="${xray_exporter_sha256}"
      if [[ -z "$${EXPECTED_SHA}" ]]; then
        echo "FATAL: xray_exporter_sha256 is unset — refusing to install unverified binary" >&2
        exit 1
      fi
      echo "$${EXPECTED_SHA}  /tmp/$${ASSET_NAME}" | sha256sum --check --strict - \
        || { echo "FATAL: xray-exporter checksum mismatch — aborting" >&2; exit 1; }
      echo "xray-exporter checksum verified against pinned value."

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
      rm -f "/tmp/$${ASSET_NAME}"
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

      # Everything this script writes is key material: the Reality private key, the
      # client UUIDs and config.json, which contains both. Branch-local umasks left
      # config.json born 0644 on every re-apply (the keypair branch is skipped once
      # the keypair exists), so set it once here and let the later chmods narrow
      # further where a group genuinely needs read.
      umask 077

      CONFIG_DIR=/etc/xray
      CONFIG_FILE=$CONFIG_DIR/config.json
      KEYPAIR_FILE=$CONFIG_DIR/keypair.env
      USERS_FILE=$CONFIG_DIR/users.txt
      CLIENTS_DIR=$CONFIG_DIR/clients
      LOG_DIR=/var/log/xray
      SNI="${vless_sni}"
      DOMAIN="${vless_domain}"
      REALITY_PORT=443
      XHTTP_PORT=10000

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
        # Everything created in this branch is Reality key material. Set the umask once
        # here so each file is created 0600, instead of being written world-readable and
        # chmod-ed a moment later.
        umask 077
        # Predictable path + ambient umask meant the Reality private key was briefly
        # readable by any local account (and the fixed name invites a pre-created
        # symlink). mktemp under umask 077 removes both; the trap covers an early exit.
        XKEY_TMP="$(umask 077; mktemp)"
        trap 'rm -f "$XKEY_TMP"' RETURN EXIT
        /usr/local/bin/xray x25519 > "$XKEY_TMP" 2>&1
        PRIVATE_KEY=$(awk '/PrivateKey:/  {print $NF}' "$XKEY_TMP")
        PUBLIC_KEY=$(awk  '/PublicKey/    {print $NF}' "$XKEY_TMP")
        SHORT_ID=$(openssl rand -hex 8)
        rm -f "$XKEY_TMP"
        if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
          echo "ERROR: failed to parse xray x25519 output — check format" >&2
          exit 1
        fi
        printf 'PRIVATE_KEY=%s\nPUBLIC_KEY=%s\nSHORT_ID=%s\n' \
          "$PRIVATE_KEY" "$PUBLIC_KEY" "$SHORT_ID" > "$KEYPAIR_FILE"
        chmod 600 "$KEYPAIR_FILE"   # belt and braces; the umask above governs creation
        echo "Generated new Reality keypair."
      else
        # Parse, never source. `source` executes the backup as shell, so a tampered or
        # merely corrupted keypair.env would run arbitrary commands as root on a freshly
        # replaced node — at the exact moment the operator is trusting the restore path.
        # Read only the three expected keys, and only when the line has the exact
        # KEY=value shape; anything else is ignored rather than evaluated.
        PRIVATE_KEY=""; PUBLIC_KEY=""; SHORT_ID=""
        while IFS= read -r kp_line || [ -n "$kp_line" ]; do
          case "$kp_line" in
            PRIVATE_KEY=*) kp_val="$${kp_line#PRIVATE_KEY=}" ; kp_name=PRIVATE_KEY ;;
            PUBLIC_KEY=*)  kp_val="$${kp_line#PUBLIC_KEY=}"  ; kp_name=PUBLIC_KEY  ;;
            SHORT_ID=*)    kp_val="$${kp_line#SHORT_ID=}"    ; kp_name=SHORT_ID    ;;
            *) continue ;;
          esac
          # Values are base64/hex key material; reject anything outside that charset so a
          # crafted value cannot survive into the rendered config or client URIs.
          case "$kp_val" in
            *[!A-Za-z0-9+/=_-]*|"")
              echo "ERROR: $KEYPAIR_FILE contains a malformed $kp_name value; refusing to restore." >&2
              exit 1 ;;
          esac
          printf -v "$kp_name" '%s' "$kp_val"
        done < "$KEYPAIR_FILE"
        echo "Loaded existing Reality keypair."
        if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" || -z "$SHORT_ID" ]]; then
          echo "ERROR: $KEYPAIR_FILE is missing PRIVATE_KEY, PUBLIC_KEY, or SHORT_ID — restore from backup or delete the file to generate a fresh keypair." >&2
          exit 1
        fi
      fi

      # This node's public IP is not known at plan time, so the box discovers it at
      # boot. Several unauthenticated third parties are tried in turn — one being down
      # (as api4.my-ip.io was) no longer wedges the whole setup. Every candidate is
      # interpolated into config.json and the client URIs, so each is format-validated
      # before use; a hostile or MITM'd reply cannot inject. A wrong-but-well-formed
      # value is the residual risk, unchanged from a single-endpoint lookup.
      vh_is_ipv4() {
        [[ "$${1:-}" =~ ^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$ ]]
      }

      SERVER_IP=""
      for url in https://api.ipify.org https://icanhazip.com https://ifconfig.me/ip https://checkip.amazonaws.com; do
        cand=$(curl -4 -fsSL --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]')
        if vh_is_ipv4 "$cand"; then SERVER_IP="$cand"; break; fi
      done

      if [ -z "$SERVER_IP" ]; then
        # Every lookup failed. Fall back to a PUBLIC address on this host — never a
        # private one: hostname -I would list any private/tunnel address too, and
        # rendering that into the client URIs would hand out a dead server address.
        echo "xray-setup: public IP lookup failed on all endpoints; trying a public host address." >&2
        for cand in $(hostname -I); do
          vh_is_ipv4 "$cand" || continue
          case "$cand" in
            10.*|127.*|169.254.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) continue ;;
          esac
          SERVER_IP="$cand"; break
        done
      fi

      if ! vh_is_ipv4 "$SERVER_IP"; then
        echo "ERROR: could not determine a public IPv4 address for this node." >&2
        echo "       Refusing to render config.json and client URIs around an unvalidated value." >&2
        exit 1
      fi

      # ── Self-address routing block ───────────────────────────────────────
      # Block traffic destined for this node's own public addresses so an
      # authenticated VLESS user cannot use the proxy as a confused deputy to
      # reach the node's own :80 / :8443 / sshd as though from outside. Emitted
      # only when the address is well-formed — an empty or malformed value would
      # render "/32" (or "/128") and make Xray fail to parse its config.
      # hcloud_server has no public_net block, so a routable IPv6 is assigned by
      # default and needs the same treatment.
      SERVER_IPV6=$(ip -6 addr show scope global 2>/dev/null \
                    | awk '/inet6/ {print $2}' | cut -d/ -f1 | head -n1)
      SELF_IP6_RULE=""
      if [[ "$${SERVER_IPV6:-}" =~ ^[0-9a-fA-F:]+$ ]]; then
        SELF_IP6_RULE="            { \"type\": \"field\", \"ip\": [\"$SERVER_IPV6/128\"], \"outboundTag\": \"block\" },"
      fi
      SELF_IP_RULE=""
      if printf '%s' "$SERVER_IP" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
        SELF_IP_RULE="            { \"type\": \"field\", \"ip\": [\"$SERVER_IP/32\"], \"outboundTag\": \"block\" },"
      else
        echo "xray-setup: WARNING - could not determine a valid public IP; the self-address routing block is omitted" >&2
      fi

      # ── Per-user UUIDs and Xray clients JSON ─────────────────────────────
      CLIENTS_JSON_REALITY=""
      CLIENTS_JSON_XHTTP=""
      SEPARATOR_R=""
      SEPARATOR_X=""

      while IFS= read -r USERNAME; do
        [[ -z "$USERNAME" || "$USERNAME" == \#* ]] && continue
        UUID_FILE="$CLIENTS_DIR/$${USERNAME}.uuid"

        if [[ -f "$UUID_FILE" ]]; then
          USER_UUID=$(cat "$UUID_FILE")
          # Restored from backup, so it is whatever the previous node wrote — and it
          # is interpolated into config.json and into every generated client URI.
          # Refuse rather than regenerate: silently minting a new UUID would revoke a
          # working client without telling anyone.
          if [[ ! "$USER_UUID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
            echo "ERROR: $UUID_FILE does not contain a UUID; refusing to render it into" >&2
            echo "       config.json and the client URIs. Remove the file to mint a new one." >&2
            exit 1
          fi
          echo "Reusing UUID for: $USERNAME"
        else
          USER_UUID=$(/usr/local/bin/xray uuid)
          # Create at 0600 rather than fixing the mode afterwards: a redirect at the
          # ambient umask is world-readable until the chmod lands.
          ( umask 077; echo "$USER_UUID" > "$UUID_FILE" )
          chmod 600 "$UUID_FILE"   # belt and braces
          echo "Generated UUID for: $USERNAME"
        fi

        if [[ "$USERNAME" == "probe" ]]; then
          # /etc/xray is 0755 and this file holds a working client credential, so a
          # redirect at the ambient umask discloses it until the chmod below lands.
          umask 077
          cat > "$CONFIG_DIR/probe-client.json" <<PROBEJSON
      {
        "log": { "loglevel": "warning" },
        "inbounds": [
          {
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": 10808,
            "protocol": "socks",
            "settings": { "udp": false }
          }
        ],
        "outbounds": [
          {
            "tag": "reality-out",
            "protocol": "vless",
            "settings": {
              "vnext": [
                {
                  "address": "$SERVER_IP",
                  "port": $REALITY_PORT,
                  "users": [
                    {
                      "id": "$USER_UUID",
                      "encryption": "none",
                      "flow": "xtls-rprx-vision"
                    }
                  ]
                }
              ]
            },
            "streamSettings": {
              "network": "tcp",
              "security": "reality",
              "realitySettings": {
                "serverName": "$SNI",
                "fingerprint": "chrome",
                "publicKey": "$PUBLIC_KEY",
                "shortId": "$SHORT_ID"
              }
            }
          }
        ]
      }
      PROBEJSON
          chown xray:xray "$CONFIG_DIR/probe-client.json"
          chmod 600 "$CONFIG_DIR/probe-client.json"
        fi

        CLIENTS_JSON_REALITY+="$${SEPARATOR_R}
                {
                  \"id\": \"$USER_UUID\",
                  \"email\": \"$USERNAME\",
                  \"flow\": \"xtls-rprx-vision\"
                }"
        SEPARATOR_R=","

        CLIENTS_JSON_XHTTP+="$${SEPARATOR_X}
                {
                  \"id\": \"$USER_UUID\",
                  \"email\": \"$USERNAME\"
                }"
        SEPARATOR_X=","

        REALITY_URI="vless://$USER_UUID@$SERVER_IP:$REALITY_PORT?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$SNI&fp=chrome&pbk=$PUBLIC_KEY&sid=$SHORT_ID&type=tcp#$USERNAME-reality"
        XHTTP_URI="vless://$USER_UUID@$DOMAIN:8443?encryption=none&security=tls&sni=$DOMAIN&fp=chrome&type=xhttp&path=%2Fapi#$USERNAME-xhttp"

        cat > "$CLIENTS_DIR/$${USERNAME}.txt" <<EOF
      # ── VLESS+Reality URI for: $USERNAME ────────────────────────────────────
      # Direct connection to the server IP. Lower latency; works wherever the IP is reachable.
      # Server: $SERVER_IP:$REALITY_PORT | SNI spoof: $SNI
      $REALITY_URI

      # ── VLESS+XHTTP URI for: $USERNAME ──────────────────────────────────────
      # TLS over HTTP/2 via $DOMAIN. Use where the server IP is blocked but the domain and port 8443 are reachable.
      # Server: $DOMAIN:8443 | Path: /api
      $XHTTP_URI
      EOF
        chmod 600 "$CLIENTS_DIR/$${USERNAME}.txt"
      done < "$USERS_FILE"

      # ── Xray server config ────────────────────────────────────────────────
      # Includes:
      #   • VLESS+Reality inbound on port 443 (direct connections, non-Iran)
      #   • VLESS+XHTTP inbound on 127.0.0.1:10000 (nginx proxies from 8443)
      #   • Stats API (gRPC) on 127.0.0.1:8080 for xray-exporter
      #   • Metrics (expvar) on 127.0.0.1:11111 for debugging
      #   • Per-user traffic stats via policy + stats blocks
      #   • Routing: block RFC-1918 + Iranian IPs/domains (prevents proxy fingerprint)
      cat > "$CONFIG_FILE" <<JSON
      {
        "log": {
          "loglevel": "warning",
          "access": "none",
          "error":  "/var/log/xray/error.log",
          "maskAddress": "full"
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
            "port": $XHTTP_PORT,
            "protocol": "vless",
            "tag": "vless_xhttp_in",
            "settings": {
              "clients": [$CLIENTS_JSON_XHTTP
              ],
              "decryption": "none"
            },
            "streamSettings": {
              "network": "xhttp",
              "security": "none",
              "xhttpSettings": { "path": "/api", "mode": "auto" }
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
            $SELF_IP_RULE
            $SELF_IP6_RULE
            { "type": "field", "ip": ["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16","100.64.0.0/10","fc00::/7","::1/128","fe80::/10"], "outboundTag": "block" },
            { "type": "field", "ip": ["geoip:ir"], "outboundTag": "block" },
            { "type": "field", "domain": ["geosite:category-ir"], "outboundTag": "block" }
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
  # The OS baseline first, so GNU coreutils are in place before anything relies on them;
  # a failure (FATAL on stderr) stops the boot here.
  - . /usr/local/lib/viaduct/os-baseline.sh && osb_baseline || exit 1
  # ── System users ──────────────────────────────────────────────────────────
  - useradd --system --no-create-home --shell /usr/sbin/nologin conduit
  - useradd --system --no-create-home --shell /usr/sbin/nologin xray
  - useradd --system --no-create-home --shell /usr/sbin/nologin alloy
  - useradd --system --no-create-home --shell /usr/sbin/nologin probe

  # ── Directories ───────────────────────────────────────────────────────────
  - mkdir -p /var/lib/conduit/data
  - chown -R conduit:conduit /var/lib/conduit
  - mkdir -p /etc/xray/clients
  - chown root:xray /etc/xray
  # 0755 let any local account reach probe-client.json and config.json.
  # Both readers run as xray:xray, so the group keeps its access.
  - chmod 0750 /etc/xray
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

  # ── Xray geo data files ───────────────────────────────────────────────────
  # geoip.dat and geosite.dat are required for routing rules that reference
  # geoip:ir and geosite:category-ir (block Iranian IP ranges/domains so the
  # server does not proxy back to Iranian infrastructure — prevents proxy
  # fingerprinting by traffic analysis). Xray looks for these files alongside
  # the binary at /usr/local/bin/.
  # Pinned to a release TAG and verified against a digest RECORDED IN THIS REPO
  # (variables.tf), not one fetched from the same release path: a party that can
  # serve a modified .dat can serve a matching .sha256sum, so an upstream sum proves
  # transport integrity only. `releases/latest/` is also unpinned — it would silently
  # install whatever the project publishes next. Run scripts/get-checksums.sh after
  # bumping geoip_version / geosite_version to refresh both digests.
  - |
    curl -fsSL "https://github.com/v2fly/geoip/releases/download/${geoip_version}/geoip.dat" -o /tmp/geoip.dat
    echo "${geoip_sha256}  /tmp/geoip.dat" | sha256sum --check --strict - \
      || { echo "FATAL: geoip.dat digest does not match the pin — aborting"; exit 1; }
    mv /tmp/geoip.dat /usr/local/bin/geoip.dat
    curl -fsSL "https://github.com/v2fly/domain-list-community/releases/download/${geosite_version}/dlc.dat" -o /tmp/dlc.dat
    echo "${geosite_sha256}  /tmp/dlc.dat" | sha256sum --check --strict - \
      || { echo "FATAL: geosite.dat digest does not match the pin — aborting"; exit 1; }
    mv /tmp/dlc.dat /usr/local/bin/geosite.dat

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

  # ── nginx: static website + XHTTP reverse proxy ──────────────────────────
  # Port 80: serves a static page (defeats active probing by DPI).
  # Port 8443: TLS proxy to xray XHTTP inbound on 127.0.0.1:10000.
  # TLS cert obtained via certbot DNS-01 challenge (no port 80 access needed).
  # The certificate is not issued here: the Cloudflare token stays out of user_data
  # (the metadata service and the hcloud API serve user_data back verbatim), so the
  # provisioner installs the credentials and runs the first certbot, then checks this
  # config with `nginx -t`. Renewals run on the box via the certbot timer.
  - mkdir -p /var/www/html
  - |
    cat > /var/www/html/index.html <<'EOF'
    <!DOCTYPE html>
    <html lang="en">
    <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Welcome</title>
    <style>body{font-family:sans-serif;max-width:600px;margin:80px auto;padding:0 20px;color:#333}</style></head>
    <body><h1>Welcome</h1><p>This site is currently under maintenance. Please check back later.</p></body>
    </html>
    EOF
  - |
    cat > /etc/nginx/conf.d/site.conf <<'NGINX_CONF'
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name _;
        server_tokens off;

        root /var/www/html;
        index index.html;

        location / {
            try_files $uri $uri/ =404;
        }
    }

    server {
        listen 8443 ssl http2;
        listen [::]:8443 ssl http2;
        server_name ${vless_domain};
        server_tokens off;

        ssl_certificate     /etc/letsencrypt/live/${vless_domain}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/${vless_domain}/privkey.pem;
        ssl_protocols       TLSv1.2 TLSv1.3;
        # HIGH still admits static-RSA key exchange (no forward secrecy) and CBC
        # suites. Name the ECDHE AEAD suites explicitly instead; every modern client
        # negotiates one of these, and TLS 1.3 suite selection is unaffected.
        ssl_ciphers         ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
        ssl_prefer_server_ciphers on;
        ssl_session_cache   shared:SSL:10m;
        ssl_session_timeout 10m;

        # Finite header/body timeouts (server scope — nginx forbids these inside a location):
        # a slow-header or slow-body client must not be able to pin a worker indefinitely.
        # These bound each connection's idle time, not per-IP volume, so clients sharing
        # one address behind carrier-grade NAT are unaffected.
        client_header_timeout 15s;
        client_body_timeout   30s;

        location /api {
            send_timeout       60s;
            proxy_pass         http://127.0.0.1:10000;
            proxy_http_version 1.1;
            proxy_set_header   Host $host;
            # XHTTP is a long-poll transport, so the upstream read timeout stays
            # generous. No per-client connection/request caps here on purpose: this
            # is the censorship-circumvention data path and its users are commonly
            # behind carrier-grade NAT (many users share one source IP), so per-IP
            # limits would throttle legitimate traffic rather than only abuse.
            proxy_read_timeout 86400s;
            proxy_buffering    off;
        }

        location / {
            return 404;
        }
    }
    NGINX_CONF
  - |
    mkdir -p /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh <<'EOF'
    #!/bin/bash
    systemctl reload nginx
    EOF
    chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
  - rm -f /etc/nginx/sites-enabled/default

  # ── Register units (do NOT start — provisioner does that) ─────────────────
  - systemctl daemon-reload
  - systemctl reload ssh   # apply SSH hardening (root login off; deploy/ops only)
  - systemctl enable conduit.service xray.service xray-exporter.service xray-user-stats.service alloy.service nginx.service xray-probe-client.service probe.service

  # ── Signal cloud-init completion ──────────────────────────────────────────
  # Only reached if all checksum verifications above passed.
  - touch /var/lib/cloud-init-done
