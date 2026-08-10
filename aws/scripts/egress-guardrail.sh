#!/usr/bin/env bash
# Egress guardrail (egress-guardrail.timer, every 15 min): read this instance's
# month-to-date NetworkOut from CloudWatch, stop the instance if it nears the
# 100 GB/mo free-tier cap. Also writes a Prometheus textfile (Alloy scrapes it) for
# the cap-headroom gauge. Uses the instance role via IMDS.
set -euo pipefail
THRESHOLD=90000000000   # 90 GB in bytes — stop below the 100 GB/mo free tier
TXTDIR=/var/lib/viaduct-textfile

TOK=$(curl -sX PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds:60")
md() { curl -s -H "X-aws-ec2-metadata-token: $TOK" "http://169.254.169.254/latest/meta-data/$1"; }
IID=$(md instance-id)
REGION=$(md placement/region)

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
EOM
mv "$TXTDIR/egress.prom.tmp" "$TXTDIR/egress.prom"

# Stop only on a reading actually obtained. Egress through the proxy is unauthenticated,
# so this action is reachable by driving traffic (VULN-036); stopping on an UNKNOWN
# reading as well would additionally hand a CloudWatch outage the same power. Per the
# operator's decision the unknown case alerts rather than stops.
if [ "$READING_VALID" -eq 1 ] && [ "$SUM" -gt "$THRESHOLD" ]; then
  echo "egress-guardrail: CAP EXCEEDED — stopping $IID"
  aws ec2 stop-instances --region "$REGION" --instance-ids "$IID"
fi
