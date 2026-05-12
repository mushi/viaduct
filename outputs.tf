output "server_ipv4" {
  value = hcloud_server.conduit.ipv4_address
}

output "server_ipv6" {
  value = hcloud_server.conduit.ipv6_address
}

output "ssh_command" {
  value = "ssh root@${hcloud_server.conduit.ipv4_address}"
}

output "conduit_status" {
  value = "ssh root@${hcloud_server.conduit.ipv4_address} 'systemctl status conduit'"
}

output "conduit_logs" {
  value = "ssh root@${hcloud_server.conduit.ipv4_address} 'journalctl -u conduit -f'"
}

output "xray_status" {
  value = "ssh root@${hcloud_server.conduit.ipv4_address} 'systemctl status xray xray-exporter'"
}

output "xray_logs" {
  value = "ssh root@${hcloud_server.conduit.ipv4_address} 'journalctl -u xray -f'"
}

output "alloy_status" {
  value = "ssh root@${hcloud_server.conduit.ipv4_address} 'systemctl status alloy'"
}

output "alloy_logs" {
  value = "ssh root@${hcloud_server.conduit.ipv4_address} 'journalctl -u alloy -f'"
}

output "vless_client_uris" {
  description = "Print all per-user VLESS URIs. Also available locally in backups/clients/<name>.txt after apply."
  value       = "ssh root@${hcloud_server.conduit.ipv4_address} 'for f in /etc/xray/clients/*.txt; do echo \"=== $f ===\"; cat \"$f\"; echo; done'"
}

output "backups_dir" {
  description = "Local directory where the provisioner downloads backups after every apply."
  value       = "${path.module}/backups/"
}
