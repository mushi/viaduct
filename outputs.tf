output "server_ipv4" {
  description = "Public IPv4 address of the Conduit server."
  value       = hcloud_server.conduit.ipv4_address
}

output "server_ipv6" {
  description = "Public IPv6 address of the Conduit server."
  value       = hcloud_server.conduit.ipv6_address
}

output "ssh_command" {
  description = "SSH command to connect to the server."
  value       = "ssh root@${hcloud_server.conduit.ipv4_address}"
}

output "service_status_command" {
  description = "Command to check Conduit service status once connected."
  value       = "ssh root@${hcloud_server.conduit.ipv4_address} 'systemctl status conduit'"
}

output "service_logs_command" {
  description = "Command to tail Conduit logs once connected."
  value       = "ssh root@${hcloud_server.conduit.ipv4_address} 'journalctl -u conduit -f'"
}
