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
    # journalctl and wg are reached only through wrappers: a sudo wildcard matches
    # the entire remaining argument string, so `journalctl *` also granted
    # --vacuum-time (destroying the audit record) and `wg show *` also granted
    # `wg show wg0 private-key`. Narrowing the patterns cannot exclude either;
    # the wrappers take fixed arguments instead. The wildcard below is on the
    # wrapper, which validates its own input — that is where the boundary lives.
    sudo: "ALL=(root) NOPASSWD: /usr/bin/systemctl status *, /usr/bin/systemctl restart *, /usr/bin/systemctl reload *, /usr/local/bin/ops-journal, /usr/local/bin/ops-journal *, /usr/local/bin/ops-wg-status"

write_files:

  # ── SSH hardening: no root login, key-only, restrict to deploy + ops ───────
  - path: /etc/ssh/sshd_config.d/10-hardening.conf
    owner: root:root
    permissions: "0644"
    content: |
      PermitRootLogin no
      PasswordAuthentication no
      AllowUsers deploy ops

  # ── SPIRE join token setter ───────────────────────────────────────────────
  # The provisioner mints a one-time join token on the GCP SPIRE server and has to
  # get it onto this node. It used to arrive as JOIN_TOKEN_ARG=-joinToken <token>
  # in an EnvironmentFile, which systemd expanded into the agent's ExecStart — so
  # the token sat in /proc/<pid>/cmdline, world-readable, for as long as the agent
  # ran. Any local process could read it and attest as this node. It now goes into
  # the root-only agent.conf, piped in over stdin so it never appears in argv here
  # either.

  - path: /usr/local/sbin/spire-agent-join-token
    owner: root:root
    permissions: "0700"
    content: |
      #!/bin/bash
      set -euo pipefail

      CONF=/opt/spire/agent/agent.conf

      read -r token
      # SPIRE tokens are UUIDs. Validate before interpolating into HCL, and reject
      # rather than write something that would change the agent's configuration.
      case "$token" in
        "" | *[!A-Za-z0-9-]* )
          echo "spire-agent-join-token: token outside [A-Za-z0-9-]; refusing" >&2
          exit 64 ;;
      esac

      umask 077
      tmp="$(mktemp "$CONF.XXXXXXXX")"
      # Drop any token from a previous provision and place the current one inside the
      # agent block — the first block in the file, so the first bare closing brace is
      # its own. Done in bash rather than sed: `0,/re/` addressing and \n in the
      # replacement are GNU extensions, and this has to behave identically wherever
      # it is exercised.
      set -f
      inserted=0
      while IFS= read -r line || [ -n "$line" ]; do
        set -- $line
        [ "$${1:-}" = "join_token" ] && continue
        if [ "$inserted" -eq 0 ] && [ "$line" = "}" ]; then
          printf '  join_token        = "%s"\n' "$token" >> "$tmp"
          inserted=1
        fi
        printf '%s\n' "$line" >> "$tmp"
      done < "$CONF"
      set +f

      if [ "$inserted" -ne 1 ]; then
        echo "spire-agent-join-token: no agent block found in $CONF; refusing" >&2
        rm -f "$tmp"
        exit 1
      fi

      chmod 0600 "$tmp"
      mv "$tmp" "$CONF"

      # Residue from the argv-based scheme, if this node predates the change.
      rm -f /opt/spire/agent/join.env

  # ── ops privilege wrappers ────────────────────────────────────────────────
  # Both exist because sudo wildcards match the whole argument string. They are
  # the only way ops reaches journalctl or wg, and they accept no pass-through
  # arguments — only a keyword the script itself resolves to a fixed command.

  - path: /usr/local/bin/ops-journal
    owner: root:root
    permissions: "0755"
    content: |
      #!/bin/bash
      # Read-only journal access for the units this node actually runs. The unit
      # name is matched against the allowlist and the *matched literal* is what
      # journalctl receives, so nothing the caller typed is ever passed through.
      set -euo pipefail

      ALLOWED="conduit xray xray-probe-client xray-exporter xray-user-stats probe alloy hetzner-secrets nginx ssh wg-quick@wg0"

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

  - path: /usr/local/bin/ops-wg-status
    owner: root:root
    permissions: "0755"
    content: |
      #!/bin/bash
      # Mesh status without the key material. Bare `wg show` prints
      # "private key: (hidden)"; `wg show <if> dump` prints it in full, which is
      # why no interface or subcommand argument is accepted here.
      set -euo pipefail

      if [ "$#" -ne 0 ]; then
        echo "usage: sudo ops-wg-status   (takes no arguments)" >&2
        exit 64
      fi

      exec /usr/bin/wg show

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

  # ── Xray probe client systemd unit ─────────────────────────────────────────────────────
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
      After=network-online.target conduit.service xray-exporter.service hetzner-secrets.service
      Wants=network-online.target hetzner-secrets.service
      # Alloy fails to start until grafana.env is rendered (see EnvironmentFile below). With
      # Restart=always it retries until then; disable the start-rate limit so it can never be
      # given up on before the Vault fetch succeeds, however long the mesh takes.
      StartLimitIntervalSec=0

      [Service]
      Type=simple
      User=alloy
      Group=alloy
      # loki.source.journal reads the systemd journal, whose files are group-readable only
      # by systemd-journal (mode 2640). Grant that group at runtime so Alloy can ship
      # journald to Loki; read-only, and it needs no persistent usermod.
      SupplementaryGroups=systemd-journal
      WorkingDirectory=/var/lib/alloy
      # Grafana Cloud creds are rendered here from Vault at boot (never on disk in /etc).
      # Required (no leading '-'): Alloy will not start until the fetch has run.
      EnvironmentFile=/run/hetzner-secrets/grafana.env
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

  # ── Vault secrets fetch: Grafana + Cloudflare from GCP Vault into tmpfs ─────
  # The node's SPIRE SVID cert-auths to GCP Vault (over the mesh) and renders
  # kv/hetzner/{grafana,cloudflare} to /run/hetzner-secrets. base64 so the multi-line
  # script embeds cleanly in YAML.
  # Shared mesh-trust helpers, sourced by fetch-hetzner-secrets.sh. Deployed
  # alongside it: the script runs from /usr/local/bin, not from the repo, so the
  # library has to land at the path the script sources.
  - path: /usr/local/bin/lib/mesh-trust.sh
    owner: root:root
    permissions: "0644"
    encoding: b64
    content: ${base64encode(mesh_trust_lib)}

  - path: /usr/local/bin/fetch-hetzner-secrets.sh
    owner: root:root
    permissions: "0755"
    encoding: b64
    content: ${base64encode(fetch_secrets_script)}

  - path: /etc/systemd/system/hetzner-secrets.service
    owner: root:root
    permissions: "0644"
    content: |
      [Unit]
      Description=Fetch Hetzner secrets from GCP Vault into tmpfs (SPIRE SVID cert-auth)
      # Needs the mesh + SPIRE agent. On first deploy those come up in provision.sh
      # (post-boot), so this fails at boot and the provisioner (re)starts it; on a
      # reboot both are already enabled, so it runs cleanly and re-renders the secrets.
      After=network-online.target wg-quick@wg0.service spire-agent.service
      Wants=network-online.target
      # No start-rate limit: the fetch may need to retry for minutes while the WireGuard
      # handshake converges, and must not be limiter-killed before it succeeds.
      StartLimitIntervalSec=0

      [Service]
      Type=oneshot
      User=viaduct-secrets
      Group=viaduct-secrets
      # setgid dir (2750) so rendered files inherit group alloy; the '+' runs as root.
      ExecStartPre=+/usr/bin/install -d -o viaduct-secrets -g alloy -m 2750 /run/hetzner-secrets
      # The mesh-handshake gate reads `wg show`, which needs CAP_NET_ADMIN — the unprivileged
      # viaduct-secrets ExecStart below cannot, so enforce it here as root ('+'). The fetch
      # runs only once the mesh has authenticated the hub; until then this fails and
      # Restart=on-failure retries. (Previously the gate lived in the fetch script and always
      # failed because viaduct-secrets gets no output from `wg show`.)
      ExecStartPre=+/bin/bash -c '. /usr/local/bin/lib/mesh-trust.sh; vh_wait_for_mesh_handshake 10.99.0.1 wg0 60'
      ExecStart=/usr/local/bin/fetch-hetzner-secrets.sh
      RemainAfterExit=yes
      # Self-heal: retry every 15s until the mesh is up and the fetch succeeds, then
      # RemainAfterExit holds it active. This is what makes a slow mesh converge not need a
      # re-provision — the provisioner's in-band attempt is now just the fast path.
      Restart=on-failure
      RestartSec=15

      [Install]
      WantedBy=multi-user.target

  # Finish-setup trigger: when the secrets finally render (however long the mesh took),
  # obtain the TLS cert if absent and (re)start the secret-dependent services, so a rebuild
  # completes hands-off with no re-provision. The .path watches the rendered file; the
  # oneshot is idempotent.
  - path: /usr/local/bin/hetzner-secrets-ready.sh
    owner: root:root
    permissions: "0755"
    content: |
      #!/usr/bin/env bash
      set -uo pipefail
      if [ -s /run/hetzner-secrets/cloudflare.ini ] && [ ! -d /etc/letsencrypt/live/${vless_domain} ]; then
        certbot certonly --dns-cloudflare --dns-cloudflare-credentials /run/hetzner-secrets/cloudflare.ini \
          -d ${vless_domain} --non-interactive --agree-tos --register-unsafely-without-email --dns-cloudflare-propagation-seconds 30 || true
      fi
      systemctl restart alloy.service 2>/dev/null || true
      [ -d /etc/letsencrypt/live/${vless_domain} ] && systemctl restart nginx.service 2>/dev/null || true

  - path: /etc/systemd/system/hetzner-secrets-ready.path
    owner: root:root
    permissions: "0644"
    content: |
      [Unit]
      Description=Trigger finish-setup when Vault secrets render
      [Path]
      PathExists=/run/hetzner-secrets/grafana.env
      Unit=hetzner-secrets-ready.service
      [Install]
      WantedBy=multi-user.target

  - path: /etc/systemd/system/hetzner-secrets-ready.service
    owner: root:root
    permissions: "0644"
    content: |
      [Unit]
      Description=Obtain TLS cert and start secret-dependent services
      [Service]
      Type=oneshot
      # Without this the .path unit above retriggers forever: a oneshot deactivates when it
      # finishes, PathExists is still true, so systemd fires it again. Each pass runs
      # `systemctl restart nginx`, so nginx exhausts its start limit and stays failed —
      # observed on a rebuild as 16 triggers and no :80 or :8443. RemainAfterExit keeps the
      # unit active once it has succeeded, which is what makes the path edge-triggered.
      RemainAfterExit=yes
      ExecStart=/usr/local/bin/hetzner-secrets-ready.sh

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

  # Cloudflare API credentials for certbot are NOT written to disk. The vault fetch
  # (hetzner-secrets.service) renders them to /run/hetzner-secrets/cloudflare.ini (tmpfs)
  # from kv/hetzner/cloudflare; certbot (initial run in provision.sh, and renewals) reads
  # them from there.

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

      # Verify against the pinned SHA-256. This release publishes no checksums
      # file, so xray-exporter is pinned in terraform.tfvars (scripts/get-checksums.sh)
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

      # This node's public IPv4 cannot be injected from Terraform (a server referencing
      # its own address in its own user_data is a dependency cycle), so the box discovers
      # it at boot. Several unauthenticated third parties are tried in turn — one being
      # down (as api4.my-ip.io was) no longer wedges the whole setup. Every candidate is
      # interpolated into config.json and client URIs, so each is format-validated before
      # use; a hostile or MITM'd reply cannot inject. A wrong-but-well-formed value is the
      # residual risk, unchanged from a single-endpoint lookup.
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
        # private or mesh one: hostname -I lists wg0's 10.99.0.2 too, and rendering that
        # into the client URIs would hand out a dead server address.
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

      # The routing blocklist below denies RFC-1918, loopback and link-local, so the
      # intent is that proxied traffic must not reach this node's own surfaces. The
      # public address is the one route back in that the list missed: a client could
      # dial it and reach :80/:8443 as though from outside. Add it as a /32.
      #
      # Emitted only when SERVER_IP looks like an IPv4 address — an empty or malformed
      # value would render "/32" into the JSON and make Xray fail to parse its config.
      # The node's own IPv6 address needs the same treatment: hcloud_server has no
      # public_net block, so a routable v6 address is assigned by default and an
      # authenticated VLESS user could otherwise dial [<node-v6>]:22 and reach sshd.
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
  # ── System users ──────────────────────────────────────────────────────────
  - useradd --system --no-create-home --shell /usr/sbin/nologin conduit
  - useradd --system --no-create-home --shell /usr/sbin/nologin xray
  - useradd --system --no-create-home --shell /usr/sbin/nologin alloy
  - useradd --system --no-create-home --shell /usr/sbin/nologin probe
  # Dedicated identity for the Vault secrets fetch; its uid is the SPIRE unix:uid selector.
  - useradd --system --no-create-home --shell /usr/sbin/nologin viaduct-secrets

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
  # Verified against digests pinned in this repository. Fetching a .sha256sum from
  # the same release path as the .dat proved transport integrity only — whatever
  # could serve a modified .dat could serve a matching sum. A recorded pin is an
  # independent reference point, which also means the release tag has to be pinned:
  # "latest" and a fixed digest cannot both hold.
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
  # The initial certbot run is NOT here: it needs the Cloudflare token from Vault,
  # which is only reachable once the mesh + SPIRE agent are up (provision.sh). The
  # provisioner obtains the cert (guarded, once) after the secrets fetch; renewals then
  # run on the box via the certbot timer, reading the tmpfs credentials.
  - |
    cat > /etc/nginx/conf.d/site.conf <<'NGINX_CONF'
    # Shared state for the per-client limits applied to the unauthenticated /api location.
    # Declared here because conf.d is included in the http context.
    limit_conn_zone $binary_remote_addr zone=api_conn:10m;
    limit_req_zone  $binary_remote_addr zone=api_req:10m rate=30r/s;
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
        client_header_timeout 15s;
        client_body_timeout   30s;

        location /api {
            # Unauthenticated and Internet-reachable, so bound what one client can hold.
            limit_conn api_conn 16;
            limit_req  zone=api_req burst=60 nodelay;

            send_timeout          60s;

            proxy_pass         http://127.0.0.1:10000;
            proxy_http_version 1.1;
            proxy_set_header   Host $host;
            # XHTTP is a long-poll transport: the upstream read timeout must stay
            # generous or legitimate sessions are cut. The limits above bound
            # concurrency and arrival rate instead, which is what makes exhaustion
            # cost the client something.
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
  - nginx -t

  # ── SPIRE agent binary + config (lab: joins the GCP SPIRE server) ─────────
  # The trust bundle (/opt/spire/agent/bootstrap.crt) and a one-time join token
  # (/opt/spire/agent/join.env) are supplied by the provisioner, which fetches
  # them from the GCP SPIRE server. The unit is enabled+started there, not here.
  - |
    curl -fsSL \
      "https://github.com/spiffe/spire/releases/download/v${spire_agent_version}/spire-${spire_agent_version}-linux-amd64-musl.tar.gz" \
      -o /tmp/spire.tar.gz
    echo "${spire_agent_sha256}  /tmp/spire.tar.gz" | sha256sum --check --strict - \
      || { echo "FATAL: SPIRE agent checksum mismatch — aborting"; exit 1; }
    tar -xzf /tmp/spire.tar.gz -C /tmp
    install -m0755 /tmp/spire-${spire_agent_version}/bin/spire-agent /usr/local/bin/spire-agent
    rm -rf /tmp/spire.tar.gz /tmp/spire-${spire_agent_version}
    mkdir -p /opt/spire/agent/data
  - |
    cat > /opt/spire/agent/agent.conf <<'AGENT_CONF'
    agent {
      data_dir          = "/opt/spire/agent/data"
      log_level         = "INFO"
      server_address    = "${spire_server_address}"
      server_port       = "8081"
      trust_domain      = "${trust_domain}"
      trust_bundle_path = "/opt/spire/agent/bootstrap.crt"
      socket_path       = "/run/spire-agent/public/api.sock"
    }
    plugins {
      NodeAttestor "join_token" { plugin_data {} }
      KeyManager "disk" { plugin_data { directory = "/opt/spire/agent/data" } }
      WorkloadAttestor "unix" { plugin_data {} }
    }
    AGENT_CONF
    # The join token is written into this file (see spire-agent-join-token), so it
    # must not be world-readable the way `cat >` under the default umask leaves it.
    chmod 0600 /opt/spire/agent/agent.conf
  - |
    cat > /etc/systemd/system/spire-agent.service <<'AGENT_UNIT'
    [Unit]
    Description=SPIRE Agent
    After=network-online.target
    Wants=network-online.target

    [Service]
    ExecStart=/usr/local/bin/spire-agent run -config /opt/spire/agent/agent.conf
    Restart=on-failure
    RestartSec=5

    [Install]
    WantedBy=multi-user.target
    AGENT_UNIT

  # ── WireGuard spoke key (lab: mesh member; provisioner finalises wg0) ──────
  # Generate the node's WireGuard key on first boot and keep it 0600 on the
  # persistent disk (Hetzner has no vTPM). The provisioner writes wg0.conf (with
  # the hub peer) and starts wg-quick; on a reboot the enabled unit reads the
  # persisted conf + key. A rebuild regenerates the key, and the provisioner
  # re-registers the new public key with the hub.
  - |
    apt-get install -y wireguard-tools
    install -d -m 0700 /etc/wireguard
    if [ ! -f /etc/wireguard/wg0.key ]; then
      ( umask 077; wg genkey > /etc/wireguard/wg0.key )
      wg pubkey < /etc/wireguard/wg0.key > /etc/wireguard/wg0.pub
    fi

  # ── Register units (do NOT start — provisioner does that) ─────────────────
  - systemctl daemon-reload
  - systemctl reload ssh   # apply SSH hardening (root login off; deploy/ops only)
  - systemctl enable conduit.service xray.service xray-exporter.service xray-user-stats.service alloy.service nginx.service xray-probe-client.service probe.service hetzner-secrets.service
  # --now so the watcher is live THIS boot (multi-user.target is already active, so a plain
  # enable would only arm it for the next boot). It fires the finish-setup oneshot as soon as
  # hetzner-secrets renders grafana.env, however long the mesh takes to converge.
  - systemctl enable --now hetzner-secrets-ready.path

  # ── Signal cloud-init completion ──────────────────────────────────────────
  # Only reached if all checksum verifications above passed.
  - touch /var/lib/cloud-init-done
