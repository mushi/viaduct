# Dead man's switch: fires when the probe's last success is over 5 min old, and on
# silence (no_data_state = Alerting) when the probe or the node stops reporting at all.
# The query must return the staleness unfiltered: a `> 300` inside the PromQL returns
# nothing while healthy, which NoData = Alerting then reports as an outage.
resource "grafana_rule_group" "dead_mans_switch" {
  name             = "Viaduct evaluation group"
  folder_uid       = grafana_folder.alerting_rules.uid
  interval_seconds = 300

  rule {
    name      = "Viaduct probe - dead man's switch"
    condition = "C"
    for       = "5m"
    is_paused = false

    no_data_state = "Alerting"
    # The only rule that reports a query it cannot run. Every other rule keeps its last
    # state through datasource errors, so this is the single signal that alerting itself
    # is blind; `for` keeps a timeout shorter than 5 min from paging.
    exec_err_state = "Error"
    annotations = {
      description = "Dead man's switch: fires when the probe or box is down."
      summary     = "vless probing has stopped. Either the probe or the box is down."
    }

    data {
      ref_id         = "A"
      datasource_uid = data.grafana_data_source.prometheus.uid
      relative_time_range {
        from = 600
        to   = 0
      }
      model = jsonencode({
        editorMode    = "code"
        expr          = "time() - probe_last_success_timestamp_seconds"
        instant       = true
        intervalMs    = 1000
        legendFormat  = "__auto"
        maxDataPoints = 43200
        range         = false
        refId         = "A"
      })
    }
    data {
      ref_id         = "C"
      query_type     = "expression"
      datasource_uid = "__expr__"
      relative_time_range {
        from = 0
        to   = 0
      }
      model = jsonencode({
        conditions = [{
          evaluator = { params = [300], type = "gt" }
          operator  = { type = "and" }
          query     = { params = ["C"] }
          reducer   = { params = [], type = "last" }
          type      = "query"
        }]
        datasource    = { type = "__expr__", uid = "__expr__" }
        expression    = "A"
        intervalMs    = 1000
        maxDataPoints = 43200
        refId         = "C"
        type          = "threshold"
      })
    }

    notification_settings {
      contact_point = var.contact_point
    }
  }
}

# The whole notification policy tree (Grafana allows exactly one). Every route goes to the
# UI-managed contact point, referenced by name so its integration URL never enters code
# or state.
resource "grafana_notification_policy" "root" {
  contact_point = var.contact_point
  group_by      = ["grafana_folder", "alertname"]
  # Several alerts stay firing for days by design (a guardrail-stopped node is down until
  # the month turns). At the 4h default that is six identical reminders a day.
  repeat_interval = "12h"

  policy {
    contact_point = var.contact_point
  }
}
