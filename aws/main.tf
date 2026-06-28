# Viaduct AWS node: own SPIRE server (trust domain viaduct.aws),
# federated with viaduct.gcp; later k3s + capped Conduit.
# Phase A1 = infrastructure only. A2 adds the SPIRE-server install via user_data.
#
# Durable vs disposable:
#   Durable: the SPIRE root CA private key lives in AWS KMS and is created +
#     managed by SPIRE's aws_kms KeyManager (NOT a Terraform resource). It is
#     keyed by alias, so it survives instance rebuilds — that is the whole point
#     of a KMS-rooted CA (nothing CA-private on disk). CAVEAT: because it is not
#     Terraform-managed, `terraform destroy` will NOT remove it; on teardown,
#     schedule its deletion manually (`aws kms schedule-key-deletion`) or it
#     lingers at ~$1/mo. The Elastic IP is a stable endpoint across rebuilds.
#   Disposable: VPC, subnet, IGW, security group, IAM role, the instance.
# Rebuild the instance without disturbing the KMS-resident CA:
#   terraform apply -replace=aws_instance.spire

# ─── AMI: latest Canonical Ubuntu 24.04 (Noble) ARM64 ────────────────────────
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd*/ubuntu-noble-24.04-arm64-server-*"]
  }
  filter {
    name   = "architecture"
    values = ["arm64"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# ─── Network (dedicated VPC, not the default) ────────────────────────────────
resource "aws_vpc" "viaduct" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "viaduct-vpc" }
}

resource "aws_internet_gateway" "viaduct" {
  vpc_id = aws_vpc.viaduct.id
  tags   = { Name = "viaduct-igw" }
}

resource "aws_subnet" "viaduct" {
  vpc_id                  = aws_vpc.viaduct.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, 0) # 10.20.0.0/28
  map_public_ip_on_launch = false                          # we attach an EIP explicitly
  tags                    = { Name = "viaduct-subnet" }
}

resource "aws_route_table" "viaduct" {
  vpc_id = aws_vpc.viaduct.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.viaduct.id
  }
  tags = { Name = "viaduct-rt" }
}

resource "aws_route_table_association" "viaduct" {
  subnet_id      = aws_subnet.viaduct.id
  route_table_id = aws_route_table.viaduct.id
}

# ─── Security group ──────────────────────────────────────────────────────────
resource "aws_security_group" "spire" {
  name        = "viaduct-aws-sg"
  description = "Viaduct AWS node: SSH + SPIRE federation bundle endpoint"
  vpc_id      = aws_vpc.viaduct.id
  tags        = { Name = "viaduct-aws-sg" }
}

resource "aws_vpc_security_group_ingress_rule" "ssh" {
  for_each          = toset(var.admin_cidr)
  security_group_id = aws_security_group.spire.id
  description       = "SSH"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = each.value
}

# SPIRE federation bundle endpoint (HTTPS), reached by the GCP SPIRE server.
# Created only once federation_cidrs is non-empty (GCP server IP known).
resource "aws_vpc_security_group_ingress_rule" "federation" {
  for_each          = toset(var.federation_cidrs)
  security_group_id = aws_security_group.spire.id
  description       = "SPIRE federation bundle endpoint"
  ip_protocol       = "tcp"
  from_port         = var.bundle_endpoint_port
  to_port           = var.bundle_endpoint_port
  cidr_ipv4         = each.value
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.spire.id
  description       = "All outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

# ─── SSH key pair ────────────────────────────────────────────────────────────
resource "aws_key_pair" "viaduct" {
  key_name   = "viaduct-aws"
  public_key = var.ssh_public_key
}

# ─── IAM: instance identity (no static keys) ─────────────────────────────────
# The instance role grants exactly two capabilities:
#   1. aws_kms KeyManager  — SPIRE creates/uses the KMS-resident CA signing key.
#   2. aws_iid NodeAttestor — server-side selector resolution for attesting agents.
resource "aws_iam_role" "spire" {
  name = "viaduct-spire-server"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# aws_kms KeyManager: SPIRE manages its own keys (created on first run, keyed by
# alias). Resource "*" because the key IDs are created dynamically by SPIRE; the
# actions are the documented aws_kms plugin set, MINUS kms:ScheduleKeyDeletion /
# kms:CancelKeyDeletion — a runtime box has no reason to destroy KMS keys, and
# withholding it stops a compromised instance from deleting the CA signing key.
# Trade-off: on rotation SPIRE can't dispose superseded keys, so they linger
# (~$1/mo each) until cleaned up at teardown.
# Stronger follow-up (test via -replace first): scope the remaining per-key
# actions by the tag SPIRE applies to its keys, instead of Resource "*".
resource "aws_iam_role_policy" "kms" {
  name = "spire-aws-kms"
  role = aws_iam_role.spire.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "kms:CreateKey",
        "kms:DescribeKey",
        "kms:GetPublicKey",
        "kms:ListKeys",
        "kms:ListAliases",
        "kms:CreateAlias",
        "kms:UpdateAlias",
        "kms:DeleteAlias",
        "kms:Sign",
        "kms:TagResource"
      ]
      Resource = "*"
    }]
  })
}

# aws_iid NodeAttestor (server side): resolve selectors for attesting agents.
resource "aws_iam_role_policy" "iid" {
  name = "spire-aws-iid"
  role = aws_iam_role.spire.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ec2:DescribeInstances", "iam:GetInstanceProfile"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_instance_profile" "spire" {
  name = "viaduct-spire-server"
  role = aws_iam_role.spire.name
}

# Egress guardrail: a host timer reads month-to-date NetworkOut from CloudWatch
# and stops THIS instance if it nears the 100 GB/mo free-tier cap. Grants only
# CloudWatch read + stop-self (scoped to this instance's ARN).
resource "aws_iam_role_policy" "guardrail" {
  name = "egress-guardrail"
  role = aws_iam_role.spire.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["cloudwatch:GetMetricStatistics"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["ec2:StopInstances"]
        Resource = aws_instance.spire.arn
      }
    ]
  })
}

# ─── Elastic IP (stable endpoint across rebuilds) ────────────────────────────
# AWS bills all public IPv4 (~$3.60/mo) whether or not attached; a stable EIP is
# worth it for a fixed SPIRE bundle endpoint + Conduit address.
resource "aws_eip" "spire" {
  domain = "vpc"
  tags   = { Name = "viaduct-aws-eip" }
}

# ─── Instance (DISPOSABLE) ───────────────────────────────────────────────────
resource "aws_instance" "spire" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.viaduct.id
  vpc_security_group_ids = [aws_security_group.spire.id]
  key_name               = aws_key_pair.viaduct.key_name
  iam_instance_profile   = aws_iam_instance_profile.spire.name

  # One-phase provisioning, runs once at instance creation: SPIRE server+agent,
  # federation, k3s, workloads, egress guardrail. k8s manifests + scripts are
  # single-sourced from k8s/ and scripts/ (injected verbatim via file()).
  # gzip'd: rendered script exceeds the 16 KB user_data cap; cloud-init decompresses.
  user_data_base64 = base64gzip(templatefile("${path.module}/scripts/startup.sh.tpl", {
    region                = var.region
    gcp_control_plane_ip  = var.gcp_control_plane_ip
    gcp_vault_fingerprint = var.gcp_vault_fingerprint
    trust_domain          = var.trust_domain
    gcp_trust_domain      = var.gcp_trust_domain
    spire_version         = var.spire_version
    spire_sha256          = var.spire_sha256
    k3s_version           = var.k3s_version
    k8s_rbac              = file("${path.module}/k8s/00-namespaces-rbac.yaml")
    k8s_csi               = file("${path.module}/k8s/01-spiffe-csi-driver.yaml")
    k8s_conduit           = file("${path.module}/k8s/10-conduit.yaml")
    k8s_alloy             = file("${path.module}/k8s/20-alloy.yaml")
    guardrail_script      = file("${path.module}/scripts/egress-guardrail.sh")
    crosscloud_script     = file("${path.module}/scripts/crosscloud-bootstrap.sh")
  }))
  # Changing user_data relaunches the instance — fine here: the SPIRE root CA is in
  # KMS (durable), so a rebuild re-attaches to it. NOT applied during the bake.
  user_data_replace_on_change = true

  # IMDSv2 required (token-based) — aws_iid fetches the identity document here.
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
    encrypted   = true
  }

  tags = { Name = var.instance_name }
}

resource "aws_eip_association" "spire" {
  instance_id   = aws_instance.spire.id
  allocation_id = aws_eip.spire.id
}
