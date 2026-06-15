terraform {
  required_version = ">= 1.3"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

# Authentication uses Application Default Credentials (ADC).
# Set up with: gcloud auth application-default login
provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}
