variable "grafana_url" {
  description = "Grafana Cloud stack URL, e.g. https://<stack>.grafana.net"
  type        = string
}

variable "grafana_auth" {
  description = "Service account token (glsa_…) with the Editor role."
  type        = string
  sensitive   = true
}

variable "contact_point" {
  description = "Existing contact point every rule notifies (managed in the UI, referenced by name)."
  type        = string
  default     = "Viaduct"
}

variable "prometheus_datasource_uid" {
  description = "UID of the stack's hosted Prometheus data source (Grafana Cloud names it grafanacloud-prom)."
  type        = string
  default     = "grafanacloud-prom"
}

variable "aws_node_present" {
  description = <<-EOT
    Whether the AWS node exists. Its rules include an absence check, which would page
    forever once the node is torn down; set false when destroying aws/ to remove them.
  EOT
  type        = bool
  default     = true
}
