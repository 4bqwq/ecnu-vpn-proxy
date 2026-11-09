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

# ARP filtering checks routes without TCP ports, so the per-port rules below
# cannot keep the Docker gateway reachable after aTrust changes the routes.
# Upstream populates table 2 with the Docker routes before starting aTrust.
docker_gateways=$(ip -4 route show default | awk '$1 == "default" && $2 == "via" { print $3 }' | sort -u)
if [[ -z "$docker_gateways" ]]; then
    echo 'Cannot find the Docker IPv4 gateway; VPN startup aborted.' >&2
    exit 1
fi
while IFS= read -r gateway; do
    ip rule add to "${gateway}/32" table 2
done <<< "$docker_gateways"

# Obtain a real address before aTrust starts, then keep it refreshed by TTL.
# The bundled Node runtime avoids an additional package or image build.
rm -f /run/ecnu-vpn-dns.ready
ELECTRON_RUN_AS_NODE=1 /usr/share/sangfor/aTrust/aTrustTray /ecnu/vpn-dns.js &
dns_pid=$!
children+=("$dns_pid")
while [[ ! -f /run/ecnu-vpn-dns.ready ]]; do
    if ! kill -0 "$dns_pid" 2>/dev/null; then
        wait "$dns_pid" || true
        echo 'VPN DNS updater exited before providing an address; see its error above.' >&2
        exit 1
    fi
    sleep 1
done

while IFS=$'\t' read -r local_port remote_host remote_port; do
    [[ -n "$local_port" ]] || continue
    ip rule add iif lo table 2 sport "$local_port"
    socat "TCP4-LISTEN:${local_port},bind=0.0.0.0,reuseaddr,fork" \
        "TCP:${remote_host}:${remote_port}" &
    children+=("$!")
done < /ecnu/forwards.tsv

/usr/local/bin/start.sh &
children+=("$!")
# A monitor failure is reported by status; it must not stop a usable VPN.
services=("${children[@]}")
ELECTRON_RUN_AS_NODE=1 /usr/share/sangfor/aTrust/aTrustTray /ecnu/recovery.js &
children+=("$!")
# A dead forwarder must be visible as a failed container, not a silent loss
# of one published port. Successful client shutdown is also propagated.
wait -n "${services[@]}"
