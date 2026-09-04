#!/usr/bin/env python3
"""Generator for dashboards/viaduct-logs.json.

The dashboard is checked in as JSON (that is what Grafana imports); this script is
how it is edited. Hand-editing 43 KB of generated JSON to move one panel is how
dashboards rot, and gridPos arithmetic is exactly the kind of thing a human gets
wrong silently — a one-cell overlap renders as a panel that is simply missing.

Every query here was validated against real log lines pulled from the three live
nodes: JSON field paths against Vault audit records, logfmt keys against
spire-server/k3s output, and both named-capture regexes against real sshd lines.
What is NOT verified is that Loki's parser accepts each expression — there is no
LogQL parser available offline, and the Grafana Cloud token is scoped logs:write,
so no query could be run. Grafana reports a parse error per panel on import.

Usage:  python3 dashboards/build-viaduct-logs.py   (run from the repo root)
"""

import json

DS = {"type": "loki", "uid": "${DS_LOKI}"}
panels, _id, y = [], [0], [0]

def nid():
    _id[0] += 1
    return _id[0]

def tgt(expr, **kw):
    t = {"refId": kw.pop("refId", "A"), "datasource": DS, "expr": expr, "editorMode": "code", "queryType": "range"}
    t.update(kw)
    return t

def add(p, w, h, x=0, newrow=False):
    if newrow or x == 0:
        pass
    p["id"] = nid()
    p["datasource"] = DS
    p["gridPos"] = {"h": h, "w": w, "x": x, "y": y[0]}
    panels.append(p)

def row(title, desc=""):
    y[0] += 1
    panels.append({"id": nid(), "type": "row", "title": title, "collapsed": False,
                   "gridPos": {"h": 1, "w": 24, "x": 0, "y": y[0]}, "panels": []})
    y[0] += 1

def bump(h):
    y[0] += h

THRESH_NEUTRAL = {"mode": "absolute", "steps": [{"color": "text", "value": None}]}
def thresh(*pairs):
    steps = [{"color": pairs[0], "value": None}]
    for c, v in zip(pairs[1::2], pairs[2::2]):
        steps.append({"color": c, "value": v})
    return {"mode": "absolute", "steps": steps}

def stat(title, desc, expr, unit="short", steps=None, graph="none"):
    return {"type": "stat", "title": title, "description": desc,
            "targets": [tgt(expr, instant=True, queryType="instant")],
            "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                        "orientation": "auto", "textMode": "auto", "colorMode": "value",
                        "graphMode": graph, "justifyMode": "auto"},
            "fieldConfig": {"defaults": {"unit": unit, "thresholds": steps or THRESH_NEUTRAL,
                                         "mappings": []}, "overrides": []}}

def ts(title, desc, targets, unit="short", stack=False, fill=0, legend="list"):
    return {"type": "timeseries", "title": title, "description": desc, "targets": targets,
            "options": {"legend": {"displayMode": legend, "placement": "bottom", "showLegend": True,
                                   "calcs": ["mean", "max"] if legend == "table" else []},
                        "tooltip": {"mode": "multi", "sort": "desc"}},
            "fieldConfig": {"defaults": {"unit": unit, "custom": {
                "drawStyle": "line", "lineWidth": 1, "fillOpacity": fill, "showPoints": "never",
                "stacking": {"mode": "normal" if stack else "none", "group": "A"},
                "spanNulls": True, "pointSize": 4},
                "thresholds": THRESH_NEUTRAL, "mappings": []}, "overrides": []}}

def logs(title, desc, expr, wrap=True, prettify=False, h_time=True):
    return {"type": "logs", "title": title, "description": desc,
            "targets": [tgt(expr)],
            "options": {"showTime": h_time, "showLabels": False, "showCommonLabels": False,
                        "wrapLogMessage": wrap, "prettifyLogMessage": prettify,
                        "enableLogDetails": True, "dedupStrategy": "none", "sortOrder": "Descending"},
            "fieldConfig": {"defaults": {}, "overrides": []}}

def table(title, desc, expr, renames, unit="short", sortby=None, desc_sort=True):
    return {"type": "table", "title": title, "description": desc,
            "targets": [tgt(expr, instant=True, queryType="instant", format="table")],
            "transformations": [
                {"id": "labelsToFields", "options": {"mode": "columns"}},
                {"id": "organize", "options": {"excludeByName": {"Time": True}, "renameByName": renames}},
            ] + ([{"id": "sortBy", "options": {"fields": {}, "sort": [{"field": sortby, "desc": desc_sort}]}}] if sortby else []),
            "options": {"showHeader": True, "cellHeight": "sm",
                        "footer": {"show": False, "reducer": ["sum"], "countRows": False, "fields": ""}},
            "fieldConfig": {"defaults": {"unit": unit, "custom": {"align": "auto", "filterable": True},
                                         "thresholds": THRESH_NEUTRAL}, "overrides": []}}

# ─────────────────────────────────────────────────────────────── header
add({"type": "text", "title": "", "transparent": True,
     "options": {"mode": "markdown", "content": (
        "## Viaduct — Fleet Logs\n"
        "Every node ships journald to Grafana Cloud Loki via Alloy, tagged `node`, `unit` and `level`. "
        "Three trust domains, three clouds, one query surface.\n\n"
        "**Read it top-down:** pipeline liveness → what the logs cost → the identity and secrets plane "
        "(this lab's whole reason to exist) → the data plane → who touched what.\n\n"
        "**Deliberately absent:** panels built on `conduit.service` `[STATS]` lines. They are ~96% of the "
        "Hetzner node's log volume and duplicate the `conduit_*` Prometheus series — and the log copy is "
        "*truncated* (`(+39 more...)`), so `conduit_region_*` is strictly better. Read throughput and "
        "per-region breakdown on the ops dashboard; this one shows what those lines **cost** instead.\n\n"
        "*Panels scoped to one node (Vault, k3s, egress guardrail) go empty if `$node` excludes it — that is "
        "honest, not broken.*")}},
    w=24, h=6)
bump(6)

# ─────────────────────────────────────────────── fleet health
row("Pipeline liveness & standing alerts")
add(stat("Nodes reporting", "Distinct `node` labels producing lines in the window. Expect 3 (gcp, hetzner, aws). "
         "Fewer means an Alloy is down, its credential expired, or the journal group grant was lost — the last of "
         "which fails silently, with every component still reporting healthy.",
         'count(sum by (node) (count_over_time({node=~"$node"} [$__range])))',
         steps=thresh("red", "orange", 2, "green", 3), graph="none"), w=4, h=5, x=0)
add(stat("Lines shipped", "Total journald lines across the selected nodes for the dashboard window.",
         'sum(count_over_time({node=~"$node"} [$__range]))'), w=4, h=5, x=4)
add(stat("Warning and above", "Lines at journal priority warning/err/crit/alert/emerg. The `level` label comes from "
         "`__journal_priority_keyword`, promoted by Alloy's relabel stage.",
         'sum(count_over_time({node=~"$node", level=~"emerg|alert|crit|err|warning"} [$__range]))',
         steps=thresh("green", "orange", 1, "red", 100)), w=4, h=5, x=8)
add(stat("Vault denials", "Vault audit records carrying a `permission denied` error — a principal reached for "
         "something its policy does not grant. Non-zero is not automatically bad (a probing script, a stale token) "
         "but every one should be explicable.",
         'sum(count_over_time({node=~"$node", unit="vault.service"} |= `permission denied` '
         '| json t="type" | t = `response` [$__range]))',
         steps=thresh("green", "orange", 1, "red", 20)), w=4, h=5, x=12)
add(stat("Break-glass root attempts", "Calls to `sys/generate-root/*`. This is the documented recovery for "
         "re-provisioning Vault and is gated by a 3-of-5 recovery-key threshold held offline — so it is rare, "
         "deliberate, and should always correlate with something you were doing. Unexplained, it is an incident.",
         'sum(count_over_time({node=~"$node", unit="vault.service"} |= `generate-root` '
         '| json p="request.path", t="type" | t = `request` | p =~ `sys/generate-root.*` [$__range]))',
         steps=thresh("green", "red", 1)), w=4, h=5, x=16)
add(stat("SSH sessions accepted", "Successful publickey authentications across the fleet. GCP is reached over IAP, "
         "AWS over SSM, Hetzner as a mesh peer — so a login from an unexpected source address is worth a look.",
         'sum(count_over_time({node=~"$node", unit=~"ssh.*"} |= `Accepted` [$__range]))',
         steps=thresh("text", "orange", 20)), w=4, h=5, x=20)
bump(5)

# ─────────────────────────────────────────────── volume & cost
row("Volume & cost")
add(ts("Line rate by node", "Lines per second, by node. Grafana Cloud bills on ingested volume, so this is a cost "
       "curve as much as an activity curve. A step change with no deployment behind it is usually a service that "
       "started retrying.",
       [tgt('sum by (node) (rate({node=~"$node"} [$__interval]))')], unit="cps", fill=8, stack=True),
    w=12, h=8, x=0)
add(ts("Byte rate by node", "Bytes per second, using LogQL's `bytes_rate`. Diverging from the line rate above means "
       "line *size* changed — verbose JSON audit records weigh far more than a one-line service notice.",
       [tgt('sum by (node) (bytes_rate({node=~"$node"} [$__interval]))')], unit="Bps", fill=8, stack=True),
    w=12, h=8, x=12)
bump(8)
add(table("Heaviest units in window", "Ranked by bytes, not lines — that is what you pay for. This is the panel that "
          "makes a runaway logger obvious. `conduit.service` sitting at the top is expected and is exactly the "
          "duplication called out in the header.",
          'topk(15, sum by (node, unit) (bytes_over_time({node=~"$node", unit=~"$unit"} | unit != "" [$__range])))',
          {"Value": "Bytes", "node": "Node", "unit": "Unit"}, unit="bytes", sortby="Bytes"),
    w=13, h=9, x=0)
add({"type": "piechart", "title": "Share of ingested bytes",
     "description": "Where the Loki bill actually goes, by unit. Reading this next to the table tells you whether "
                    "your volume is one loud service or broad-based.",
     "targets": [tgt('topk(10, sum by (unit) (bytes_over_time({node=~"$node", unit=~"$unit"} | unit != "" [$__range])))',
                     instant=True, queryType="instant")],
     "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                 "pieType": "donut", "displayLabels": ["percent"],
                 "legend": {"displayMode": "table", "placement": "right", "showLegend": True, "values": ["value"]},
                 "tooltip": {"mode": "single", "sort": "desc"}},
     "fieldConfig": {"defaults": {"unit": "bytes", "custom": {"hideFrom": {}}}, "overrides": []}},
    w=11, h=9, x=13)
bump(9)

# ─────────────────────────────────────────────── identity & secrets
row("Identity & secrets — Vault and SPIRE")
add(ts("Vault requests by principal", "Who is talking to Vault. No single audit field names the principal: "
       "`auth.metadata.role_name` is the most specific but is set on under half of requests, `auth.display_name` "
       "covers most of the rest, and pre-authentication requests (a login itself) legitimately have neither. "
       "`label_format` resolves that with a template fallback chain rather than dropping records, so the series "
       "add up to the real request rate.\n\n"
       "Expect `spire-server` renewing its token continuously, `gcp-viaduct-controlplane` for anything using the "
       "box's GCE identity, and `cert-aws-vault-agent` when the AWS Alloy pod starts. A principal you did not "
       "deploy, or a familiar one changing rate sharply, is the signal.",
       [tgt('sum by (principal) (count_over_time({node=~"$node", unit="vault.service"} '
            '| json t="type", role="auth.metadata.role_name", disp="auth.display_name" | t = `request` '
            '| label_format principal=`{{ if .role }}{{ .role }}{{ else if .disp }}{{ .disp }}'
            '{{ else }}(unauthenticated){{ end }}` [$__interval]))')],
       unit="cps", legend="table"), w=12, h=9, x=0)
add(ts("SPIRE federation heartbeat", "Each SPIRE server polling its peer's trust bundle, split by which node did "
       "the polling and which trust domain it fetched. Both directions should be continuously present — gcp "
       "refreshing `viaduct.aws` and aws refreshing `viaduct.gcp`, roughly every 75s.\n\n"
       "**This exists only in logs.** No metric covers federation liveness, so a silent half of this panel is the "
       "earliest warning that cross-cloud trust is decaying — well before an SVID actually fails to validate.",
       [tgt('sum by (node, trust_domain) (count_over_time({node=~"$node", unit="spire-server.service"} '
            '| logfmt | msg = `Bundle refreshed` [$__interval]))')], unit="cps", legend="table"),
    w=12, h=9, x=12)
bump(9)
add(table("Vault paths touched", "Every secret path reached in the window, with the operation and the role that "
          "reached it. This is the audit question — *who read what* — answered directly. `kv/data/*/grafana` is the "
          "observability credential; `kv/data/wireguard/peers/*` is mesh registration; `auth/token/renew-self` is "
          "routine token upkeep.",
          'topk(20, sum by (path, op, principal) (count_over_time({node=~"$node", unit="vault.service"} '
          '| json t="type", path="request.path", op="request.operation", role="auth.metadata.role_name", '
          'disp="auth.display_name" | t = `request` | path != "" '
          '| label_format principal=`{{ if .role }}{{ .role }}{{ else if .disp }}{{ .disp }}'
          '{{ else }}(unauthenticated){{ end }}` [$__range])))',
          {"Value": "Calls", "path": "Path", "op": "Operation", "principal": "Principal"}, sortby="Calls"),
    w=12, h=10, x=0)
add(logs("Vault denials", "Audit responses carrying `permission denied`, reduced to the four things you want: "
         "operation, path, principal, source. `line_format` turns a 2 KB JSON record into one readable line — the "
         "full record is still there under the row expander.\n\n"
         "A denial is not automatically an attack; it is usually a policy boundary doing its job. The worked "
         "example in this deployment: `sys/generate-root/attempt` denied to `gcp-viaduct-controlplane`, because "
         "the CWE-863 remediation removed the admin policy's blanket `sys/*` grant. That is the control working — "
         "and is exactly what the `enable_unauthenticated_access = [\"generate-root\"]` listener setting was added "
         "to resolve. Denials on `auth/gcp/role/*` are the same story: admin deliberately cannot mint auth roles.",
         '{node=~"$node", unit="vault.service"} |= `permission denied` '
         '| json t="type", path="request.path", op="request.operation", role="auth.metadata.role_name", '
         'disp="auth.display_name", addr="request.remote_address" | t = `response` '
         '| label_format principal=`{{ if .role }}{{ .role }}{{ else if .disp }}{{ .disp }}'
         '{{ else }}(unauthenticated){{ end }}` '
         '| line_format `DENIED  {{ .op }} {{ .path }}   principal={{ .principal }}  from={{ .addr }}`', wrap=True),
    w=12, h=10, x=12)
bump(10)
add(logs("Break-glass: root token generation", "Any call to `sys/generate-root/*`. Regenerating a root token is the "
         "documented path for re-provisioning Vault and needs 3 of 5 recovery keys held offline — so this panel "
         "should be empty except when you are deliberately doing that. It is given its own panel precisely because "
         "it must never scroll past unnoticed in a general log view.",
         '{node=~"$node", unit="vault.service"} |= `generate-root` '
         '| json t="type", path="request.path", op="request.operation", addr="request.remote_address" '
         '| t = `request` | path =~ `sys/generate-root.*` '
         '| line_format `{{ .op }} {{ .path }}  from={{ .addr }}`'),
    w=24, h=7, x=0)
bump(7)

# ─────────────────────────────────────────────── data plane
row("Data plane & node services")
add(logs("Conduit lifecycle", "`conduit.service` with the `[STATS]` firehose filtered out (`!=` on the line), "
         "leaving starts, stops, capacity settings and errors. This is the whole reason a line filter beats a "
         "unit filter: the useful events are 4% of the stream and invisible without it.",
         '{node=~"$node", unit="conduit.service"} != `[STATS]`'), w=12, h=8, x=0)
add(logs("Xray, nginx & certbot", "The rest of the Hetzner ingress path: the proxy, the TLS terminator that fronts "
         "XHTTP, and certificate renewal. Certbot is quiet by design — DNS-01 renewals every 60 days — so anything "
         "here at all is worth reading.",
         '{node=~"$node", unit=~"xray.service|nginx.service|certbot.*"}'), w=12, h=8, x=12)
bump(8)
add(logs("AWS egress guardrail", "The free-tier cap guard on the AWS node. It reads `aws_mtd_egress_bytes` from the "
         "textfile collector and stops the Conduit pod as the monthly cap approaches — so its log is the record of "
         "how close you came, and whether it ever actually fired.",
         '{node=~"$node", unit="egress-guardrail.service"}'), w=12, h=8, x=0)
add(logs("SPIRE agents & k3s errors", "Agent attestation and SVID rotation across both trust domains, plus anything "
         "k3s logs at error level. `logfmt` then a label filter is the idiomatic way to drop k3s's very chatty "
         "info-level COMPACT stream without a brittle line match.",
         '{node=~"$node", unit=~"spire-agent.service|k3s.service"} | logfmt | level =~ `error|warning|warn`'),
    w=12, h=8, x=12)
bump(8)

# ─────────────────────────────────────────────── access
row("Access & security")
add(logs("SSH sessions accepted", "Successful publickey logins, with user, source and key type pulled out by a "
         "named-capture `regexp` stage and reformatted. Backtick-quoted so the regex needs no escaping.\n\n"
         "Expected sources: `35.235.240.0/20` on GCP (that is IAP), the SSM agent on AWS, and your mesh address "
         "`10.99.0.4` on Hetzner. Anything else is the finding.",
         '{node=~"$node", unit=~"ssh.*"} |= `Accepted` '
         '| regexp `Accepted (?P<method>\\S+) for (?P<user>\\S+) from (?P<src>\\S+) port (?P<sport>\\d+)` '
         '| line_format `{{ .user }}  <-  {{ .src }}   ({{ .method }})`'), w=12, h=9, x=0)
add(table("Rejected SSH by source", "Failed and invalid-user attempts grouped by source IP. Only Hetzner exposes "
          "`:22` at all — GCP and AWS have no public SSH — so this is essentially the internet background noise "
          "hitting one host, and it is useful mainly as a baseline you would notice changing.",
          'topk(15, sum by (src) (count_over_time({node=~"$node", unit=~"ssh.*"} '
          '|~ `(?i)invalid user|failed password|authentication failure` '
          '| regexp `(?P<src>\\d+\\.\\d+\\.\\d+\\.\\d+)` | src != "" [$__range])))',
          {"Value": "Attempts", "src": "Source IP"}, sortby="Attempts"), w=12, h=9, x=12)
bump(9)

# ─────────────────────────────────────────────── explorer
row("Explorer")
add(logs("Fleet log explorer", "Everything, with all four template variables applied — node, unit, level and a "
         "case-insensitive substring. This is the panel you actually drive during an incident; the ones above exist "
         "so you know where to point it.",
         '{node=~"$node", unit=~"$unit", level=~"$level"} |~ `(?i)$search`'), w=24, h=14, x=0)
bump(14)

# ── normalise template stages ────────────────────────────────────────────────
# `regexp` keeps backtick raw strings (it needs \S and \d unescaped). `label_format`
# and `line_format` move to the documented double-quoted form; none of our templates
# contain a double quote, so this is a straight substitution.
import re as _re
def _norm(expr):
    expr = _re.sub(r'label_format (\w+)=`([^`]*)`', r'label_format \1="\2"', expr)
    expr = _re.sub(r'line_format `([^`]*)`', r'line_format "\1"', expr)
    return expr
for _p in panels:
    for _t in _p.get("targets", []):
        _t["expr"] = _norm(_t["expr"])

dash = {
    "annotations": {"list": [{
        "builtIn": 1, "name": "Annotations & Alerts", "type": "dashboard",
        "iconColor": "rgba(0, 211, 255, 1)", "enable": True, "hide": True}]},
    "editable": True,
    "graphTooltip": 1,
    "time": {"from": "now-6h", "to": "now"},
    "refresh": "1m",
    "schemaVersion": 39,
    "title": "Viaduct — Fleet Logs",
    "uid": "viaduct-fleet-logs",
    "tags": ["viaduct", "logs", "loki", "security"],
    "timezone": "browser",
    "templating": {"list": [
        {"type": "datasource", "name": "DS_LOKI", "label": "Loki", "query": "loki",
         "hide": 0, "current": {}, "refresh": 1, "regex": "", "skipUrlSync": False},
        {"type": "query", "name": "node", "label": "Node", "datasource": DS,
         "query": "label_values(node)", "refresh": 2, "multi": True, "includeAll": True,
         "allValue": ".+", "current": {"text": "All", "value": "$__all"}, "sort": 1,
         "definition": "label_values(node)", "hide": 0, "options": [], "skipUrlSync": False},
        {"type": "query", "name": "unit", "label": "Unit", "datasource": DS,
         "query": 'label_values({node=~"$node"}, unit)', "refresh": 2, "multi": True,
         "includeAll": True, "allValue": ".*", "current": {"text": "All", "value": "$__all"},
         "sort": 1, "definition": 'label_values({node=~"$node"}, unit)', "hide": 0,
         "options": [], "skipUrlSync": False},
        {"type": "query", "name": "level", "label": "Level", "datasource": DS,
         "query": "label_values(level)", "refresh": 2, "multi": True, "includeAll": True,
         "allValue": ".*", "current": {"text": "All", "value": "$__all"}, "sort": 1,
         "definition": "label_values(level)", "hide": 0, "options": [], "skipUrlSync": False},
        {"type": "textbox", "name": "search", "label": "Search", "query": "",
         "current": {"text": "", "value": ""}, "hide": 0, "options": [], "skipUrlSync": False},
    ]},
    "panels": panels,
}
open(__import__("os").path.join(__import__("os").path.dirname(__file__), "viaduct-logs.json"), "w").write(json.dumps(dash, indent=2) + "\n")
print(f"wrote {len(panels)} panels")
