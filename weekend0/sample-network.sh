#!/bin/sh
# Sample W0 ports with the standard macOS/POSIX command-line tools.
set -u
umask 077
LC_ALL=C
export LC_ALL

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    printf 'Usage: sh sample-network.sh HOST NETWORK [OUTPUT_DIRECTORY]\n' >&2
    exit 2
fi
host=$1
network=$2
case "$host" in ''|*[!a-z0-9.-]*) printf 'Invalid test hostname.\n' >&2; exit 2;; esac
case "$network" in ''|*[!A-Za-z0-9_-]*) printf 'Invalid network label.\n' >&2; exit 2;; esac
if [ "${#network}" -gt 32 ]; then printf 'Network label is too long.\n' >&2; exit 2; fi
command -v curl >/dev/null 2>&1 || { printf 'curl is required.\n' >&2; exit 2; }
output=${3:-"$HOME/nethub-w0-results"}
mkdir -p "$output" || exit 2
output=$(cd "$output" && pwd -P) || exit 2
ancestor=$output
while :; do
    if [ -e "$ancestor/.git" ]; then
        printf 'Keep network evidence outside repositories.\n' >&2
        exit 2
    fi
    [ "$ancestor" = / ] && break
    ancestor=$(dirname "$ancestor")
done
stamp=$(date -u '+%Y%m%d-%H%M%S')
raw="$output/$network-$stamp.csv"
sanitized="$output/$network-$stamp.sanitized.csv"
if [ -e "$raw" ] || [ -e "$sanitized" ]; then
    printf 'An evidence file already exists; retain it and start a new run.\n' >&2
    exit 2
fi
printf 'Network,Round,Port,StartedUtc,CurlExit,HttpCode,TcpConnected,TimeConnect,TimeAppConnect,TimeTotal,AddressFamily,RemoteAddress,SourceAddress\n' > "$raw" || exit 2
round=1
while [ "$round" -le 20 ]; do
    for port in 443 8443; do
        started=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
        metrics=$(curl -4 --noproxy '*' -o /dev/null -s -k --connect-timeout 5 --max-time 10 \
            -w '%{http_code},%{time_connect},%{time_appconnect},%{time_total},%{remote_ip},%{local_ip}' \
            "https://$host:$port/")
        code=$?
        printf '%s\n' "$metrics" | awk -F, -v network="$network" -v round="$round" -v port="$port" -v started="$started" -v code="$code" '
            NF != 6 || $1 !~ /^[0-9][0-9][0-9]$/ {exit 2}
            $2 !~ /^[0-9]+([.][0-9]+)?$/ || $3 !~ /^[0-9]+([.][0-9]+)?$/ || $4 !~ /^[0-9]+([.][0-9]+)?$/ {exit 2}
            {printf "%s,%d,%d,%s,%d,%s,%s,%s,%s,%s,IPv4,%s,%s\n", network,round,port,started,code,$1,($2+0>0?"True":"False"),$2,$3,$4,$5,$6}
        ' >> "$raw" || { printf 'Unexpected curl metrics; retain the partial private CSV.\n' >&2; exit 2; }
        printf 'Round %s/20, port %s: curl exit %s\n' "$round" "$port" "$code"
    done
    [ "$round" -eq 20 ] || sleep 2
    round=$((round + 1))
done
awk -F, 'BEGIN {OFS=","} {print $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11}' "$raw" > "$sanitized" || exit 2
awk -F, '
    NR>1 && $3==443 && $7=="True" {baseline++}
    NR>1 && $3==8443 && $7=="True" {tunnel++}
    END {printf "SamplesPerPort=20 Tcp443=%d Tcp8443=%d DifferencePercentagePoints=%d Q2Triggered=%s BothZero=%s\n",baseline,tunnel,5*(baseline-tunnel),(baseline-tunnel>=4 || tunnel==0?"True":"False"),(baseline==0 && tunnel==0?"True":"False")}
' "$raw"
printf 'SanitizedCsv=%s\nPrivateCsv=%s\n' "$sanitized" "$raw"
