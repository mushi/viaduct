output "instance_public_ip" {
  description = "Stable Elastic IP of the AWS node (Conduit address; admin is via SSM, not SSH)."
  value       = aws_eip.spire.public_ip
}

output "instance_id" {
  description = "EC2 instance ID."
  value       = aws_instance.spire.id
}

output "ssm_session" {
  description = "Open an admin shell on the AWS node (no public SSH; SSM only)."
  value       = "aws ssm start-session --region ${var.region} --target ${aws_instance.spire.id}"
}

output "bundle_endpoint_url" {
  description = "SPIRE federation bundle endpoint the GCP server fetches, over the WireGuard mesh (public :8443 is closed post-lockdown)."
  value       = "https://${var.wg_mesh_ip}:${var.bundle_endpoint_port}"
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
  description = "Ubuntu 24.04 ARM64 AMI the running instance was built from (ami is under ignore_changes)."
  value       = aws_instance.spire.ami
}

output "latest_ami_id" {
  description = "Newest Ubuntu 24.04 ARM64 AMI; differs from ami_id when a -replace would move to a newer image."
  value       = data.aws_ami.ubuntu.id
}
