# Viaduct alert rules generated from a rule list. The dead man's switch and the
# notification policy are in alerting.tf; the contact point stays UI-managed. Group names
# must stay distinct from any group created in the UI: a rule group is written as a
# whole, so a same-named group would replace the rules already in it.
#
# Every rule is an instant PromQL query that returns a positive value per firing
# series, with a `> threshold` condition on it.

data "grafana_data_source" "prometheus" {
  uid = var.prometheus_datasource_uid
}

locals {
  # The egress guardrail (aws/scripts/egress-guardrail.sh) publishes these gauges every
  # 15 min through the node's Alloy. Throttling starts at 70% of the cap; pausing Conduit
  # needs two consecutive readings over it. Each rule names what it means and what to do.
  aws_rules = [
    {
      name      = "AWS node silent"
      expr      = "absent_over_time(aws_mtd_egress_reading_valid{node=\"aws\"}[20m])"
      threshold = 0
      for       = "10m"
      summary   = "No metrics from the AWS node for 30 min"
      # The guardrail pauses Conduit at the cap and leaves the node up, so this is never
      # the cap: the node is stopped, crashed, or its Alloy is not shipping.
      description = "Stopped, crashed, or Alloy not shipping. The egress guardrail never stops the node (it pauses Conduit instead), so check the instance state and `journalctl -u k3s` / the alloy pod over SSM."
    },
    {
      name        = "AWS egress near cap"
      expr        = "max(aws_mtd_egress_bytes{node=\"aws\"}) / max(aws_egress_cap_bytes{node=\"aws\"})"
      threshold   = 0.9
      for         = "0s"
      summary     = "AWS month-to-date egress above 90% of the cap"
      description = "The guardrail pauses Conduit on two consecutive readings over the cap. At the normal rate that is typically a day or two away."
    },
    {
      name        = "Conduit paused at egress cap"
      expr        = "max(aws_conduit_paused{node=\"aws\"})"
      threshold   = 0
      for         = "0s"
      summary     = "The egress guardrail has paused Conduit on the AWS node"
      description = "Month-to-date egress passed the cap. The node, SPIRE and the mesh stay up; the guardrail resumes Conduit on its own once a new month's reading is under the cap. Nothing to do unless it is still paused after the 1st: RUNBOOK, Recovery, 'Conduit paused by the egress guardrail'."
    },
    {
      name        = "AWS egress throttled"
      expr        = "max(aws_egress_throttled{node=\"aws\"})"
      threshold   = 0
      for         = "1h"
      summary     = "AWS node shaped to 2 mbit for over an hour"
      description = "Month-to-date egress passed 70% of the cap. Something is spending the budget; the node still serves, slowly. Check conduit_* traffic before it reaches the cap."
    },
    {
      name        = "AWS egress reading unavailable"
      expr        = "max(1 - aws_mtd_egress_reading_valid{node=\"aws\"})"
      threshold   = 0
      for         = "1h"
      summary     = "Guardrail cannot read NetworkOut from CloudWatch"
      description = "The egress cap is not being enforced while this fires. Check the instance role's cloudwatch:GetMetricStatistics and `journalctl -u egress-guardrail`."
    },
    {
      name        = "AWS egress state not persisted"
      expr        = "max(1 - aws_egress_state_persisted{node=\"aws\"})"
      threshold   = 0
      for         = "30m"
      summary     = "Guardrail cannot write /var/lib/viaduct-guardrail/last"
      description = "The two-reading check cannot arm, so the egress cap is not being enforced. Check the disk on the AWS node."
    },
    {
      name        = "AWS egress reading implausible"
      expr        = "max(1 - aws_mtd_egress_reading_plausible{node=\"aws\"})"
      threshold   = 0
      for         = "0s"
      summary     = "MTD egress jumped more than 20 GB in one 15-min window"
      description = "More than the node can emit; a CloudWatch anomaly or backfill. The stop is withheld on this reading. Compare with CloudWatch NetworkOut directly."
    },
  ]

  # A user whose last 24h downlink fell below 5% of their own 7-day daily average, with
  # the baseline offset 24h so the window under test is excluded from it. count by
  # (user) yields 1 per affected user, so a total collapse (ratio exactly 0, a
  # null-routed IP) still crosses `> 0`. The 50 MB/day floor keeps light users quiet.
  user_rules = [
    {
      name        = "User traffic collapsed"
      expr        = <<-EOT
        count by (user) (
          (
            sum by (user) (increase(xray_user_downlink_bytes_total{job="xray_user_stats"}[24h]))
            /
            (sum by (user) (increase(xray_user_downlink_bytes_total{job="xray_user_stats"}[7d] offset 24h)) / 7)
            < 0.05
          )
          and
          (sum by (user) (increase(xray_user_downlink_bytes_total{job="xray_user_stats"}[7d] offset 24h)) / 7) > 50e6
        )
      EOT
      threshold   = 0
      for         = "6h"
      summary     = "{{ $labels.user }}: traffic collapsed against their own baseline"
      description = "Blocked or departed. A trickle (KB/day) means the client is still trying: likely blocked, see RUNBOOK 'Rotating the Hetzner public IP'. Flat zero: ask them. Expect noise for a week after a rebuild (counter resets)."
    },
  ]
}

# Rules whose notification should open on a dashboard panel. The panel id is looked up
# by title in the dashboard JSON, so a renumbered panel cannot leave a stale link.
locals {
  vless_dashboard = jsondecode(file("${path.module}/dashboards/${local.dashboards.vless_xray}"))
  rule_panel_links = {
    "User traffic collapsed" = {
      __dashboardUid__ = grafana_dashboard.viaduct["vless_xray"].uid
      __panelId__ = tostring(one([
        for p in local.vless_dashboard.panels : p.id if p.title == "Per-user: last 24h vs own baseline"
      ]))
    }
  }
}

# The AWS group is dropped with the node (aws_node_present = false): its absence rule
# would otherwise page for as long as the node is gone.
locals {
  groups = merge(
    var.aws_node_present ? {
      aws_egress = { name = "Viaduct AWS egress", interval = 60, labels = { node = "aws" }, rules = local.aws_rules }
    } : {},
    {
      users = { name = "Viaduct users", interval = 300, labels = {}, rules = local.user_rules }
    },
  )
}

resource "grafana_rule_group" "viaduct" {
  for_each         = local.groups
  name             = each.value.name
  folder_uid       = grafana_folder.alerting_rules.uid
  interval_seconds = each.value.interval

  dynamic "rule" {
    for_each = each.value.rules
    content {
      name      = rule.value.name
      condition = "C"
      for       = rule.value.for
      # An instant query that matches nothing is the healthy state for every rule here
      # (absent_over_time included), so NoData must not page. A query that cannot run
      # (a datasource timeout) keeps the previous state: with Error, every rule sent its
      # own DatasourceError and a firing alert was knocked out and re-fired on each
      # timeout. Sustained evaluation failure is reported once, by the dead man's switch.
      no_data_state  = "OK"
      exec_err_state = "KeepLast"
      labels         = each.value.labels
      annotations = merge(
        {
          summary     = rule.value.summary
          description = rule.value.description
        },
        lookup(local.rule_panel_links, rule.value.name, {}),
      )

      data {
        ref_id         = "A"
        datasource_uid = data.grafana_data_source.prometheus.uid
        relative_time_range {
          from = 600
          to   = 0
        }
        model = jsonencode({
          refId   = "A"
          expr    = rule.value.expr
          instant = true
          range   = false
        })
      }
      data {
        ref_id         = "C"
        datasource_uid = "__expr__"
        relative_time_range {
          from = 0
          to   = 0
        }
        model = jsonencode({
          refId      = "C"
          type       = "threshold"
          expression = "A"
          conditions = [{ evaluator = { type = "gt", params = [rule.value.threshold] } }]
        })
      }

      notification_settings {
        contact_point = var.contact_point
      }
    }
  }
}
