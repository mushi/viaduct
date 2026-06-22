output "instance_public_ip" {
  description = "Stable Elastic IP of the AWS node (SSH here, and the SPIRE bundle-endpoint / Conduit address)."
  value       = aws_eip.spire.public_ip
}

output "instance_id" {
  description = "EC2 instance ID."
  value       = aws_instance.spire.id
}

output "ssh_command" {
  description = "Ready-to-run SSH one-liner."
  value       = "ssh ${var.ssh_user}@${aws_eip.spire.public_ip}"
}

output "bundle_endpoint_url" {
  description = "SPIRE federation bundle endpoint the GCP server will fetch (live in A2/A3)."
  value       = "https://${aws_eip.spire.public_ip}:${var.bundle_endpoint_port}"
}

output "iam_role_arn" {
  description = "Instance role (aws_kms KeyManager + aws_iid NodeAttestor)."
  value       = aws_iam_role.spire.arn
}

output "trust_domain" {
  description = "SPIFFE trust domain of this server."
  value       = var.trust_domain
}

output "ami_id" {
  description = "Resolved Ubuntu 24.04 ARM64 AMI."
  value       = data.aws_ami.ubuntu.id
}
