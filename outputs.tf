output "server_ipv4" {
  value = hcloud_server.conduit.ipv4_address
}

output "server_ipv6" {
  value = hcloud_server.conduit.ipv6_address
}

output "ssh_command" {
  value = "ssh ops@${hcloud_server.conduit.ipv4_address}"
}

output "conduit_status" {
  value = "ssh ops@${hcloud_server.conduit.ipv4_address} 'sudo systemctl status conduit'"
}

output "conduit_logs" {
  value = "ssh ops@${hcloud_server.conduit.ipv4_address} 'sudo ops-journal conduit follow'"
}

output "xray_status" {
  value = "ssh ops@${hcloud_server.conduit.ipv4_address} 'sudo systemctl status xray xray-exporter'"
}

output "xray_logs" {
  value = "ssh ops@${hcloud_server.conduit.ipv4_address} 'sudo ops-journal xray follow'"
}

output "alloy_status" {
  value = "ssh ops@${hcloud_server.conduit.ipv4_address} 'sudo systemctl status alloy'"
}

output "alloy_logs" {
  value = "ssh ops@${hcloud_server.conduit.ipv4_address} 'sudo ops-journal alloy follow'"
}

output "vless_client_uris" {
  description = "Print all per-user VLESS URIs. Downloaded locally to backups/clients/<name>.txt after every apply."
  value       = "cat ${path.module}/backups/clients/*.txt"
}

output "backups_dir" {
  description = "Local directory where the provisioner downloads backups after every apply."
  value       = "${path.module}/backups/"
}
