#cloud-config

# Applied once on first boot. Installs the Conduit CLI binary from the
# official Psiphon GitHub release and configures a systemd service to
# keep it running permanently.

package_update: true
package_upgrade: true
packages:
  - curl
  - ca-certificates
  - unattended-upgrades

write_files:
  # ── systemd service unit ──────────────────────────────────────────────────
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

      # The data directory holds conduit_key.json (proxy identity/reputation)
      # and traffic_state.json. Preserving this across restarts is important:
      # Psiphon's broker builds reputation per key, so losing it means
      # starting from zero and receiving fewer client connections initially.
      WorkingDirectory=/var/lib/conduit

      ExecStart=/usr/local/bin/conduit start \
        --data-dir /var/lib/conduit/data \
        --bandwidth ${conduit_bandwidth} \
        --max-common-clients ${conduit_max_clients}

      # Restart automatically on any failure, with a 10 s back-off
      Restart=always
      RestartSec=10

      # Give the process time to shut down gracefully
      TimeoutStopSec=30

      # Hardening: restrict what the service can do
      NoNewPrivileges=true
      PrivateTmp=true
      ProtectSystem=strict
      ProtectHome=true
      ReadWritePaths=/var/lib/conduit
      CapabilityBoundingSet=
      AmbientCapabilities=

      [Install]
      WantedBy=multi-user.target

  # ── automatic security updates config ────────────────────────────────────
  - path: /etc/apt/apt.conf.d/20auto-upgrades
    owner: root:root
    permissions: "0644"
    content: |
      APT::Periodic::Update-Package-Lists "1";
      APT::Periodic::Unattended-Upgrade "1";
      APT::Periodic::AutocleanInterval "7";

runcmd:
  # ── Create dedicated unprivileged user ───────────────────────────────────
  - useradd --system --no-create-home --shell /usr/sbin/nologin conduit

  # ── Create persistent data directory ─────────────────────────────────────
  - mkdir -p /var/lib/conduit/data
  - chown -R conduit:conduit /var/lib/conduit

  # ── Download the official Conduit binary ─────────────────────────────────
  # The official release binary includes an embedded Psiphon config, so no
  # separate config file is required.
  - |
    curl -fsSL \
      "https://github.com/Psiphon-Inc/conduit/releases/download/${conduit_version}/conduit-linux-amd64" \
      -o /usr/local/bin/conduit
  - chmod +x /usr/local/bin/conduit

  # ── Enable and start the service ─────────────────────────────────────────
  - systemctl daemon-reload
  - systemctl enable conduit.service
  - systemctl start conduit.service
