terraform {
  required_version = ">= 1.4"

  required_providers {
    grafana = {
      source  = "grafana/grafana"
      version = "~> 4.0"
    }
  }
}

# A Grafana Cloud service account token (Administration → Users and access → Service
# accounts) with the Editor role. Provider config is never written to state.
provider "grafana" {
  url  = var.grafana_url
  auth = var.grafana_auth
}
