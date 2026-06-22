terraform {
  required_version = ">= 1.3"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Authentication uses the default AWS credential chain (env vars, shared config,
# or SSO). Verify with: aws sts get-caller-identity
provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project = "viaduct"
    }
  }
}
