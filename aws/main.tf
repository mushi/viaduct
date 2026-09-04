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
  description = "Viaduct AWS node: SSH + SPIRE federation bundle endpoint" # immutable; change forces a replace
  vpc_id      = aws_vpc.viaduct.id
  tags        = { Name = "viaduct-aws-sg" }
}

# No inbound rules by design. The SPIRE federation bundle endpoint (8443) listens
# on 0.0.0.0 but GCP fetches it over the WireGuard mesh (10.99.0.3): mesh packets
# arrive decrypted on wg0, which the security group never sees, so no ingress rule
# is needed. Admin is over SSM (outbound). Re-exposing 8443 publicly requires adding
# a new ingress rule here (a reviewable change), not flipping a variable.

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.spire.id
  description       = "All outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
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
# alias). Resource "*" because the key IDs are created dynamically by SPIRE.
# kms:ScheduleKeyDeletion IS granted so SPIRE auto-prunes superseded keys on
# rotation (SPIRE rotates often; otherwise they linger at ~$1/mo each). It is the
# only destructive action SPIRE's prune needs. kms:CancelKeyDeletion stays
# withheld: SPIRE never needs it, and withholding it means a compromised box can
# at worst schedule a deletion, which KMS holds in a 7-30 day pending window that
# only the operator identity can cancel. ScheduleKeyDeletion is scoped by TAG, not
# alias: SPIRE repoints a key's alias to its replacement BEFORE pruning the old key,
# so an alias condition (kms:ResourceAliases) matches nothing on the orphaned key and
# denies the prune — the key then lingers. SPIRE tags every key it creates
# (key_tags in the aws_kms KeyManager config), and that tag survives the alias move,
# so kms:ResourceTag confines deletion to SPIRE's own keys AND still lets it prune.
# The two must stay in sync (test_kms_key_tag_matches_policy). This is no weaker than
# alias-scoping: with unconditioned CreateAlias/UpdateAlias the box can already mark an
# arbitrary key before deleting it either way — the condition prevents blanket deletion,
# which is the finding.
resource "aws_iam_role_policy" "kms" {
  name = "spire-aws-kms"
  role = aws_iam_role.spire.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Operations AWS cannot resource-scope: CreateKey has no resource yet, and the
      # List* actions are account-level by definition. CreateAlias AND UpdateAlias act on a
      # key that has no SPIRE_SERVER/ alias yet — on X509 CA rotation SPIRE creates a fresh
      # key and repoints the alias to it, and a kms:ResourceAliases condition reads the
      # TARGET key's *existing* aliases (none, so it matches nothing and denies the
      # rotation → the server crash-loops). TagResource is the same. What remains here is
      # enumeration, key creation and alias management — no signing, no key destruction
      # (those stay resource-scoped below).
      {
        Effect = "Allow"
        Action = [
          "kms:CreateKey",
          "kms:DescribeKey",
          "kms:GetPublicKey",
          "kms:ListKeys",
          "kms:ListAliases",
          "kms:CreateAlias",
          "kms:UpdateAlias",
          "kms:TagResource"
        ]
        Resource = "*"
      },
      # Alias-scoped operations, on the keys SPIRE addresses through its SPIRE_SERVER/
      # aliases. kms:ResourceAliases confines them to those keys. Signing belongs here:
      # unscoped it let the instance role sign with every asymmetric KMS key in the
      # account. SPIRE aliases a key before it ever signs with it, and DeleteAlias
      # naturally acts on a live SPIRE_SERVER/ alias — both hold while the alias exists.
      {
        Effect = "Allow"
        Action = [
          "kms:DeleteAlias",
          "kms:Sign"
        ]
        Resource = "*"
        Condition = {
          "ForAnyValue:StringLike" = {
            "kms:ResourceAliases" = ["alias/SPIRE_SERVER/*"]
          }
        }
      },
      # Key destruction, scoped by TAG. A rotated key's alias is repointed to its
      # replacement before the prune runs, so the orphaned key has no SPIRE_SERVER/
      # alias and an alias condition would deny its deletion. SPIRE tags every key it
      # creates (viaduct-managed-by=spire-server; see aws/scripts/startup.sh.tpl), and
      # that tag persists across the alias move, so this both confines deletion to
      # SPIRE's own keys and lets the prune actually succeed. Without this the instance
      # role could schedule deletion of any KMS key in the account.
      {
        Effect = "Allow"
        Action = [
          "kms:ScheduleKeyDeletion"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ResourceTag/viaduct-managed-by" = "spire-server"
          }
        }
      }
    ]
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

# Session Manager policy
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.spire.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
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
  iam_instance_profile   = aws_iam_instance_profile.spire.name

  # One-phase provisioning, runs once at instance creation: SPIRE server+agent,
  # federation, k3s, workloads, egress guardrail. k8s manifests + scripts are
  # single-sourced from k8s/ and scripts/ (injected verbatim via file()).
  # gzip'd: rendered script exceeds the 16 KB user_data cap; cloud-init decompresses.
  # Strip full-line comments (keep shebangs) from the rendered user_data so it fits EC2's
  # 16 KiB limit — the campaign's manifests + scripts + the grown mesh-trust lib pushed it to
  # ~24 KiB. The source files keep their comments; only the deployed copy is lean (~13.4 KiB).
  user_data_base64 = base64gzip(replace(templatefile("${path.module}/scripts/startup.sh.tpl", {
    region               = var.region
    wg_hub_ip            = var.wg_hub_ip
    trust_domain         = var.trust_domain
    gcp_trust_domain     = var.gcp_trust_domain
    spire_version        = var.spire_version
    spire_sha256         = var.spire_sha256
    k3s_version          = var.k3s_version
    k3s_installer_sha256 = var.k3s_installer_sha256
    awscli_version       = var.awscli_version
    awscli_zip_sha256    = var.awscli_zip_sha256
    k8s_rbac             = file("${path.module}/k8s/00-namespaces-rbac.yaml")
    k8s_csi              = file("${path.module}/k8s/01-spiffe-csi-driver.yaml")
    k8s_conduit          = file("${path.module}/k8s/10-conduit.yaml")
    k8s_alloy            = file("${path.module}/k8s/20-alloy.yaml")
    guardrail_script     = file("${path.module}/scripts/egress-guardrail.sh")
    crosscloud_script    = file("${path.module}/scripts/crosscloud-bootstrap.sh")
    # Shared mesh-trust helpers live at the repo root so both provisioners use one
    # copy; crosscloud-bootstrap.sh runs from /opt/viaduct on the node, so the
    # library is installed next to it by startup.sh.tpl.
    mesh_trust_lib = file("${path.module}/../scripts/lib/mesh-trust.sh")
  }), "/(?m)^[[:blank:]]*#([^!].*)?$/", ""))
  # IMDSv2 required (token-based) — aws_iid fetches the identity document here.
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
    # Pin the response hop limit to 1 so IMDS is reachable only from the host itself,
    # never from a pod one hop away behind the CNI. AWS defaults this to 1, but pinning
    # it makes the intent explicit and immune to a default/launch-path drift — the same
    # control HuggingFace added after an agent read node-role credentials from a pod via
    # IMDS (169.254.169.254) and pivoted from there.
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
    encrypted   = true
  }

  tags = { Name = var.instance_name }

  # Uniform -replace model across all three roots (GCP, Hetzner, AWS): a boot-script
  # edit never auto-rebuilds. ignore_changes on user_data_base64 mirrors Hetzner's
  # ignore_changes=[user_data], so a plain apply ignores startup-script drift. To
  # apply an edited startup script, rebuild explicitly:
  #   terraform apply -replace=aws_instance.spire
  # What survives a rebuild: the CA private keys persist in KMS, but the CA journal
  # lives in the ephemeral sqlite datastore, so a rebuild mints a FRESH viaduct.aws
  # CA and the trust bundle changes (the old KMS keys orphan and auto-prune). The
  # federation-sync terraform_data re-pushes the new bundle to GCP.
  lifecycle {
    ignore_changes = [user_data_base64]
  }
}

resource "aws_eip_association" "spire" {
  instance_id   = aws_instance.spire.id
  allocation_id = aws_eip.spire.id
}
