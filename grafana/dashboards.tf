# Dashboards are code-first: the JSON in grafana/dashboards/ is the source of truth. To change
# one, edit it in the UI and save, then copy the classic JSON model (not the v2 resource)
# over its file with the top-level "id" and "version" removed; `terraform plan` should
# then show no changes. A plan that wants to revert a dashboard means a UI edit was never
# copied back. Dashboard URLs are keyed on the uid inside the JSON, so keep it stable.
#
# moav-*.json extend the MoaV Conduit dashboard
# (github.com/shayanb/MoaV, configs/monitoring/grafana/provisioning/dashboards/conduit.json);
# moav-multi-node.json adapts it to several Conduit nodes.

locals {
  dashboards = {
    viaduct_ops     = "viaduct-ops.json"
    viaduct_sli     = "viaduct-sli.json"
    viaduct_logs    = "viaduct-logs.json"
    vless_xray      = "vless-xray-dashboard.json"
    moav_conduit    = "moav-conduit.json"
    moav_multi_node = "moav-multi-node.json"
  }
}

resource "grafana_dashboard" "viaduct" {
  for_each    = local.dashboards
  folder      = grafana_folder.viaduct.uid
  config_json = file("${path.module}/dashboards/${each.value}")
}
