output "server_ipv4" {
  value = hcloud_server.conduit.ipv4_address
}

output "server_ipv6" {
  value = hcloud_server.conduit.ipv6_address
}

output "ssh_command" {
  value = "ssh -i ${var.ops_ssh_key_path} ops@${var.wg_mesh_ip}"
}

output "conduit_status" {
  value = "ssh -i ${var.ops_ssh_key_path} ops@${var.wg_mesh_ip} 'sudo systemctl status conduit'"
}

output "conduit_logs" {
  value = "ssh -i ${var.ops_ssh_key_path} ops@${var.wg_mesh_ip} 'sudo journalctl -u conduit -f'"
}

output "xray_status" {
  value = "ssh -i ${var.ops_ssh_key_path} ops@${var.wg_mesh_ip} 'sudo systemctl status xray xray-exporter'"
}

output "xray_logs" {
  value = "ssh -i ${var.ops_ssh_key_path} ops@${var.wg_mesh_ip} 'sudo journalctl -u xray -f'"
}

output "alloy_status" {
  value = "ssh -i ${var.ops_ssh_key_path} ops@${var.wg_mesh_ip} 'sudo systemctl status alloy'"
}

output "alloy_logs" {
  value = "ssh -i ${var.ops_ssh_key_path} ops@${var.wg_mesh_ip} 'sudo journalctl -u alloy -f'"
}

output "wireguard_status" {
  description = "Show the WireGuard mesh interface on the data-plane node (private key hidden)."
  value       = "ssh -i ${var.ops_ssh_key_path} ops@${var.wg_mesh_ip} 'sudo wg show wg0'"
}

output "vless_client_uris" {
  description = "Print all per-user VLESS URIs. Also available locally in backups/clients/<name>.txt after apply."
  value       = "cat ${path.module}/backups/clients/*.txt"
}

output "backups_dir" {
  description = "Local directory where the provisioner downloads backups after every apply."
  value       = "${path.module}/backups/"
}
