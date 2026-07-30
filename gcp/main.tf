# Viaduct control-plane node (GCP): Vault + SPIRE server.
# Phase 1 = infrastructure only. Phase 2 adds the Vault + SPIRE install via
# metadata.startup-script.
#
# Durable vs disposable:
#   Durable (prevent_destroy): KMS key ring, KMS unseal key, snapshot bucket.
#     These MUST survive instance rebuilds or restored Vault data cannot be
#     unsealed.
#   Disposable: instance, network, subnet, firewall, service account.
# Rebuild the instance without touching durable resources:
#   terraform apply -replace=google_compute_instance.controlplane

# ─── Network (dedicated VPC, not the default) ────────────────────────────────
resource "google_compute_network" "viaduct" {
  name                    = "viaduct-net"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "viaduct" {
  name          = "viaduct-subnet"
  ip_cidr_range = "10.10.0.0/24"
  region        = var.region
  network       = google_compute_network.viaduct.id
}

# Static external IP: a stable control-plane endpoint for the agents and a
# stable SAN for Vault's self-signed listener cert across instance rebuilds.
# In-use cost is the same as an ephemeral IP.
resource "google_compute_address" "controlplane" {
  name   = "viaduct-controlplane-ip"
  region = var.region
}

# ─── Firewall ────────────────────────────────────────────────────────────────
# SSH via IAP TCP forwarding: traffic arrives only from Google's IAP proxy
# range (35.235.240.0/20), IAM-gated.
resource "google_compute_firewall" "iap_ssh" {
  name      = "viaduct-allow-iap-ssh"
  network   = google_compute_network.viaduct.name
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"]
  target_tags   = ["viaduct-controlplane"]
}

# WireGuard hub: the single public UDP port for the private mesh overlay, and the
# only world-facing ingress on this node. The GCP node is the hub; Hetzner, AWS, and the
# operator dial in. WireGuard silently drops any packet not signed by a configured
# peer, so 0.0.0.0/0 is a safe default (the crypto is the gate); tighten wg_ingress_cidrs
# to the spoke IPs if you prefer, accepting the IP-churn maintenance.
resource "google_compute_firewall" "wireguard" {
  name      = "viaduct-allow-wireguard"
  network   = google_compute_network.viaduct.name
  direction = "INGRESS"

  allow {
    protocol = "udp"
    ports    = [tostring(var.wg_port)]
  }

  source_ranges = var.wg_ingress_cidrs
  target_tags   = ["viaduct-controlplane"]
}

# No public control-plane ingress by design. Vault (8200), the SPIRE server API
# (8081) and the SPIRE federation bundle endpoint (8443) listen on 0.0.0.0 but are
# reachable ONLY over the WireGuard mesh (10.99.0.1): mesh packets arrive decrypted
# on wg0 and are delivered locally, which the VPC firewall never sees, so no allow
# rule is needed for them. Re-exposing any of these publicly requires adding a new
# firewall rule here (a reviewable change), not flipping a variable. Break-glass to
# Vault is over IAP SSH to the box, then 127.0.0.1:8200 — never the public IP.

# ─── Service account (instance identity; no static key) ──────────────────────
resource "google_service_account" "controlplane" {
  account_id   = "viaduct-controlplane"
  display_name = "Viaduct control plane (Vault + SPIRE server)"
}

# ─── KMS: Vault auto-unseal (DURABLE) ────────────────────────────────────────
resource "google_kms_key_ring" "vault" {
  name     = "viaduct-vault"
  location = var.region

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "vault_unseal" {
  name     = "vault-unseal"
  key_ring = google_kms_key_ring.vault.id
  purpose  = "ENCRYPT_DECRYPT"

  # Auto-rotate every 90 days. KMS retains prior versions for decrypt and Vault's
  # gcpckms seal selects the version embedded in the ciphertext, so rotation is
  # transparent to auto-unseal (new wraps use the new primary version).
  rotation_period = "7776000s"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "vault_unseal" {
  crypto_key_id = google_kms_crypto_key.vault_unseal.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.controlplane.email}"
}

# Vault's gcpckms seal also performs a cryptoKeys.get existence check at startup,
# which cryptoKeyEncrypterDecrypter does not include. Grant read-only metadata
# (scoped to this key).
resource "google_kms_crypto_key_iam_member" "vault_unseal_viewer" {
  crypto_key_id = google_kms_crypto_key.vault_unseal.id
  role          = "roles/cloudkms.viewer"
  member        = "serviceAccount:${google_service_account.controlplane.email}"
}

# ─── Vault Raft snapshot bucket (DURABLE) ────────────────────────────────────
resource "google_storage_bucket" "vault_snapshots" {
  name                        = var.snapshot_bucket_name
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  # Snapshots write to a fixed key (vault.snap); keep the 3 most recent versions.
  lifecycle_rule {
    condition {
      num_newer_versions = 3
      with_state         = "ARCHIVED"
    }
    action {
      type = "Delete"
    }
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_storage_bucket_iam_member" "vault_snapshots" {
  bucket = google_storage_bucket.vault_snapshots.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.controlplane.email}"
}

# Google APIs required at runtime / by Terraform. Declared explicitly so a from-scratch
# deploy doesn't fail mid-flight: compute + iam are called by Vault's `gcp` auth (instance
# + service-account lookup); cloudresourcemanager backs the project-IAM bindings below.
resource "google_project_service" "required" {
  for_each = toset([
    "compute.googleapis.com",
    "iam.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iap.googleapis.com", # IAP TCP forwarding for SSH without public ingress
  ])
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false # shared APIs — don't disable them on teardown
}

# Lets Vault's `gcp` auth method verify operator logins by GCE instance identity
# (type=gce): the backend reads the calling instance (compute.instances.get) and resolves
# its service account (iam.serviceAccounts.get) to match the role's bound_service_accounts.
# Used for the operator `admin` role so the root token can be revoked.
resource "google_project_iam_member" "vault_gcp_auth_compute_viewer" {
  project = var.project_id
  role    = "roles/compute.viewer" # compute.instances.get
  member  = "serviceAccount:${google_service_account.controlplane.email}"
}

resource "google_project_iam_member" "vault_gcp_auth_sa_viewer" {
  project = var.project_id
  role    = "roles/iam.serviceAccountViewer" # iam.serviceAccounts.get
  member  = "serviceAccount:${google_service_account.controlplane.email}"
}

# ─── Instance (DISPOSABLE) ───────────────────────────────────────────────────
resource "google_compute_instance" "controlplane" {
  name         = var.instance_name
  machine_type = var.machine_type
  zone         = var.zone
  tags         = ["viaduct-controlplane"]

  # Some in-place changes (machine_type, shielded/secure-boot config, service
  # account) require Terraform to stop the instance. Default false so a stop is
  # never a surprise; set true deliberately when you intend a stop-and-start.
  allow_stopping_for_update = var.allow_stopping_for_update

  boot_disk {
    initialize_params {
      image = var.boot_image
      size  = 30
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.viaduct.id
    access_config {
      nat_ip = google_compute_address.controlplane.address
    }
  }

  service_account {
    email  = google_service_account.controlplane.email
    scopes = ["cloud-platform"]
  }

  # Secure boot + vTPM + integrity monitoring (Ubuntu GCE images are
  # shielded-VM compatible).
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    # Only the instance-level ssh-keys below grant access; ignore project-wide keys.
    block-project-ssh-keys = "true"
    ssh-keys               = "${var.ssh_user}:${var.ssh_public_key}"
    startup-script         = file("${path.module}/scripts/startup.sh")
    region                 = var.region
    kms-keyring            = google_kms_key_ring.vault.name
    kms-cryptokey          = google_kms_crypto_key.vault_unseal.name
    vault-version          = var.vault_version
    vault-addr-ip          = google_compute_address.controlplane.address

    spire-version         = var.spire_version
    spire-sha256          = var.spire_sha256
    spire-approle-role-id = var.spire_approle_role_id
    trust-domain          = var.trust_domain

    aws-certrole-approle-role-id = var.aws_certrole_approle_role_id
    wg-port                      = tostring(var.wg_port)
    aws-spire-ip                 = var.aws_spire_ip

    snapshot-approle-role-id = var.snapshot_approle_role_id
    snapshot-bucket          = google_storage_bucket.vault_snapshots.name

    # Operator's one-time Vault bootstrap helper, delivered to /usr/local/bin by
    # startup.sh. Kept a standalone file so it is reviewable and lintable.
    bootstrap-vault-script = file("${path.module}/scripts/bootstrap-vault.sh")
  }
}
