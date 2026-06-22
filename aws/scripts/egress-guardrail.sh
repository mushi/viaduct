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
SUM=${SUM%.*}; { [ -z "$SUM" ] || [ "$SUM" = "None" ]; } && SUM=0
echo "egress-guardrail: MTD NetworkOut = $(awk -v s="$SUM" 'BEGIN{printf "%.2f", s/1e9}') GB (cap $((THRESHOLD/1000000000)) GB)"

mkdir -p "$TXTDIR"
cat > "$TXTDIR/egress.prom.tmp" <<EOM
# HELP aws_mtd_egress_bytes Month-to-date NetworkOut (CloudWatch)
# TYPE aws_mtd_egress_bytes gauge
aws_mtd_egress_bytes $SUM
# HELP aws_egress_cap_bytes Auto-stop egress cap (bytes)
# TYPE aws_egress_cap_bytes gauge
aws_egress_cap_bytes $THRESHOLD
EOM
mv "$TXTDIR/egress.prom.tmp" "$TXTDIR/egress.prom"

if [ "$SUM" -gt "$THRESHOLD" ]; then
  echo "egress-guardrail: CAP EXCEEDED — stopping $IID"
  aws ec2 stop-instances --region "$REGION" --instance-ids "$IID"
fi
