#!/bin/bash
set -euo pipefail

# Upstream keeps the original Docker routes in table 2. Forwarding replies
# must use those routes even after aTrust has installed its VPN routes.
children=()
stop_children() {
    for child in "${children[@]}"; do
        kill "$child" 2>/dev/null || true
    done
    wait || true
}
trap stop_children EXIT
trap 'exit 0' TERM INT

while IFS=$'\t' read -r local_port remote_host remote_port; do
    [[ -n "$local_port" ]] || continue
    ip rule add iif lo table 2 sport "$local_port"
    socat "TCP4-LISTEN:${local_port},bind=0.0.0.0,reuseaddr,fork" \
        "TCP:${remote_host}:${remote_port}" &
    children+=("$!")
done < /ecnu/forwards.tsv

/usr/local/bin/start.sh &
children+=("$!")
# A dead forwarder must be visible as a failed container, not a silent loss
# of one published port. Successful client shutdown is also propagated.
wait -n "${children[@]}"
