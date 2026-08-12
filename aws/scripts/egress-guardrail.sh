#!/usr/bin/env bash
# Egress guardrail (egress-guardrail.timer, every 15 min): read this instance's
# month-to-date NetworkOut from CloudWatch, stop the instance if it nears the
# 100 GB/mo free-tier cap. Also writes a Prometheus textfile (Alloy scrapes it) for
# the cap-headroom gauge. Uses the instance role via IMDS.
set -euo pipefail
THRESHOLD=90000000000     # 90 GB in bytes — hard cap, below the 100 GB/mo free tier
WARN_THRESHOLD=63000000000 # 70% of the cap — throttle here, long before stopping
# A 15-minute delta larger than this is not a real workload on this instance
# (conduit is capped at --bandwidth 15 x --max-common-clients 5 = 75 Mbps peak,
# about 8 GB per window). A bigger jump means a CloudWatch anomaly or a backfill,
# and must not by itself be grounds for the terminal action.
MAX_DELTA=20000000000
TXTDIR=/var/lib/viaduct-textfile
STATEDIR=/var/lib/viaduct-guardrail

TOK=$(curl -sX PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds:60")
md() { curl -s -H "X-aws-ec2-metadata-token: $TOK" "http://169.254.169.254/latest/meta-data/$1"; }
IID=$(md instance-id)
REGION=$(md placement/region)

# Never fatal: if iproute2 is unavailable the shaper is simply unavailable, and the
# cap still gets enforced. Aborting here would disable the guardrail altogether,
# which is a worse failure than not being able to throttle.
IFACE=""
if command -v ip >/dev/null 2>&1 && command -v tc >/dev/null 2>&1; then
  IFACE=$(ip route show default 2>/dev/null | awk '{print $5}' | head -n1 || true)
fi

# ── Throttle, not stop, as the first response ────────────────────────────────
# Egress through the proxy is unauthenticated, so anything that ends in
# `ec2 stop-instances` is an availability control an outsider can aim at the node.
# Shaping the interface degrades service instead of ending it, and multiplies the
# time needed to reach the hard cap — which buys the alert time to be seen.
#
# WireGuard is exempted: the mesh carries SPIRE federation and Vault access, and
# throttling the control plane to defend a bandwidth budget trades one outage for
# another.
throttle_is_on() {
  [ -n "$IFACE" ] || return 1
  tc qdisc show dev "$IFACE" 2>/dev/null | grep -q 'qdisc htb 1:'
}
throttle_on() {
  [ -n "$IFACE" ] || { echo "egress-guardrail: no tc/default interface; cannot throttle" >&2; return 1; }
  throttle_is_on && return 0
  tc qdisc replace dev "$IFACE" root handle 1: htb default 20
  tc class replace dev "$IFACE" parent 1: classid 1:1 htb rate 1000mbit
  tc class replace dev "$IFACE" parent 1:1 classid 1:10 htb rate 200mbit ceil 1000mbit
  tc class replace dev "$IFACE" parent 1:1 classid 1:20 htb rate 2mbit ceil 4mbit
  # WireGuard (udp/51820) keeps the fast class so the mesh survives the throttle.
  tc filter replace dev "$IFACE" protocol ip parent 1: prio 1 u32 \
    match ip protocol 17 0xff match ip dport 51820 0xffff flowid 1:10
  tc filter replace dev "$IFACE" protocol ip parent 1: prio 1 u32 \
    match ip protocol 17 0xff match ip sport 51820 0xffff flowid 1:10
  echo "egress-guardrail: THROTTLED $IFACE to 2mbit (mesh exempt)"
}
throttle_off() {
  throttle_is_on || return 0
  tc qdisc del dev "$IFACE" root 2>/dev/null || true
  echo "egress-guardrail: throttle released on $IFACE"
}

START=$(date -u +%Y-%m-01T00:00:00Z); NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
SUM=$(aws cloudwatch get-metric-statistics --region "$REGION" \
  --namespace AWS/EC2 --metric-name NetworkOut \
  --dimensions Name=InstanceId,Value="$IID" \
  --start-time "$START" --end-time "$NOW" --period 86400 --statistics Sum \
  --query 'sum(Datapoints[].Sum)' --output text)
# "Could not read" and "no egress this month" are different facts. Collapsing both to 0
# meant the comparison below could never fire, so a persistent CloudWatch failure
# disabled the cap silently and indefinitely, with the textfile reporting a reassuring
# 0.00 GB throughout.
SUM=${SUM%.*}
READING_VALID=1
REPORTED_SUM="$SUM"
if [ -z "$SUM" ] || [ "$SUM" = "None" ]; then
  READING_VALID=0
  SUM=0
  # Publish NaN rather than 0. A dashboard or alert that reads only the byte gauge would
  # otherwise see a reassuring 0.00 GB; NaN cannot be mistaken for "no egress".
  REPORTED_SUM="NaN"
  echo "egress-guardrail: WARNING — CloudWatch returned no usable NetworkOut reading." >&2
  echo "                  Treating month-to-date egress as UNKNOWN, not zero. The cap is" >&2
  echo "                  not enforced for this run; alert on aws_mtd_egress_reading_valid." >&2
else
  echo "egress-guardrail: MTD NetworkOut = $(awk -v s="$SUM" 'BEGIN{printf "%.2f", s/1e9}') GB (cap $((THRESHOLD/1000000000)) GB)"
fi

# Previous reading, so a single implausible jump is visible as one. Losing the state
# file is not fatal: without it PREV_OVER stays 0 and the ladder simply never reaches
# the terminal rung, which errs toward staying up. That is the safe direction, but it
# does mean the cap stops being enforced — hence the gauge.
STATE_OK=1
mkdir -p "$STATEDIR" 2>/dev/null || STATE_OK=0
PREV_SUM=0; PREV_OVER=0
[ -r "$STATEDIR/last" ] && read -r PREV_SUM PREV_OVER < "$STATEDIR/last" || true
case "$PREV_SUM" in ''|*[!0-9]*) PREV_SUM=0 ;; esac
case "$PREV_OVER" in ''|*[!0-9]*) PREV_OVER=0 ;; esac

DELTA=0
PLAUSIBLE=1
if [ "$READING_VALID" -eq 1 ]; then
  [ "$SUM" -ge "$PREV_SUM" ] && DELTA=$((SUM - PREV_SUM)) || DELTA=0   # month rollover resets
  if [ "$DELTA" -gt "$MAX_DELTA" ]; then
    PLAUSIBLE=0
    echo "egress-guardrail: WARNING — MTD egress jumped $(awk -v d="$DELTA" 'BEGIN{printf "%.1f", d/1e9}') GB" >&2
    echo "                  in one window, beyond what this instance can emit. Treating the" >&2
    echo "                  reading as suspect: throttling and alerting, not stopping." >&2
  fi
fi

# Act first, then publish, so aws_egress_throttled describes this run.
if [ "$READING_VALID" -eq 1 ] && [ "$SUM" -gt "$WARN_THRESHOLD" ]; then
  throttle_on || true
elif [ "$READING_VALID" -eq 1 ]; then
  throttle_off || true
fi

THROTTLE_STATE=0
throttle_is_on && THROTTLE_STATE=1

mkdir -p "$TXTDIR"
cat > "$TXTDIR/egress.prom.tmp" <<EOM
# HELP aws_mtd_egress_bytes Month-to-date NetworkOut (CloudWatch). Meaningless when
# aws_mtd_egress_reading_valid is 0 — alert on that gauge, not on a low byte count.
# TYPE aws_mtd_egress_bytes gauge
aws_mtd_egress_bytes $REPORTED_SUM
# HELP aws_mtd_egress_reading_valid 1 when the CloudWatch reading was obtained, 0 when it
# could not be read. A sustained 0 means the egress cap is not being enforced.
# TYPE aws_mtd_egress_reading_valid gauge
aws_mtd_egress_reading_valid $READING_VALID
# HELP aws_egress_cap_bytes Auto-stop egress cap (bytes)
# TYPE aws_egress_cap_bytes gauge
aws_egress_cap_bytes $THRESHOLD
# HELP aws_egress_warn_bytes Throttle threshold; above this the interface is shaped.
# TYPE aws_egress_warn_bytes gauge
aws_egress_warn_bytes $WARN_THRESHOLD
# HELP aws_egress_throttled 1 when the egress shaper is installed. Sustained 1 means
# something is driving the budget — investigate before it reaches the cap.
# TYPE aws_egress_throttled gauge
aws_egress_throttled $THROTTLE_STATE
# HELP aws_mtd_egress_delta_bytes Change in MTD NetworkOut since the previous run.
# TYPE aws_mtd_egress_delta_bytes gauge
aws_mtd_egress_delta_bytes $DELTA
# HELP aws_mtd_egress_reading_plausible 0 when the delta exceeded what this instance
# can physically emit in one window; the terminal stop is withheld on such a reading.
# TYPE aws_mtd_egress_reading_plausible gauge
aws_mtd_egress_reading_plausible $PLAUSIBLE
# HELP aws_egress_state_persisted 1 when the previous reading could be stored. A 0 means
# the sustained-reading check cannot arm and the cap is therefore not enforced.
# TYPE aws_egress_state_persisted gauge
aws_egress_state_persisted $STATE_OK
EOM
mv "$TXTDIR/egress.prom.tmp" "$TXTDIR/egress.prom"

# Escalation ladder. Egress through the proxy is unauthenticated, so `stop-instances`
# is an availability control an outsider can aim at this node (VULN-036). It is now
# the last rung, not the first:
#
#   below WARN          release any throttle, do nothing
#   WARN..CAP           shape the interface, alert, keep serving
#   above CAP, once     shape and alert — one reading is not a trend
#   above CAP, twice    stop, having already throttled and alerted for >= 15 min
#
# An outsider must therefore sustain traffic through a 2 mbit pipe across two
# consecutive windows to force the stop, with aws_egress_throttled pinned at 1
# throughout. Stopping on an UNKNOWN reading would additionally hand a CloudWatch
# outage the same power; per the operator's decision that case alerts rather than stops.
OVER=0
if [ "$READING_VALID" -eq 1 ] && [ "$SUM" -gt "$THRESHOLD" ]; then OVER=1; fi

if [ "$OVER" -eq 1 ] && [ "$PLAUSIBLE" -eq 1 ] && [ "$PREV_OVER" -eq 1 ]; then
  echo "egress-guardrail: CAP EXCEEDED on two consecutive readings — stopping $IID"
  aws ec2 stop-instances --region "$REGION" --instance-ids "$IID"
elif [ "$OVER" -eq 1 ]; then
  echo "egress-guardrail: CAP EXCEEDED — throttled and alerting; will stop if the next" >&2
  echo "                  reading is still over. aws_egress_throttled=1" >&2
fi

printf '%s %s\n' "$SUM" "$OVER" > "$STATEDIR/last" 2>/dev/null || STATE_OK=0
[ "$STATE_OK" -eq 1 ] || echo "egress-guardrail: WARNING — cannot persist $STATEDIR/last; the" \
  "sustained-reading check cannot arm, so the cap will not be enforced. Alert on" \
  "aws_egress_state_persisted." >&2
