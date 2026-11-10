#!/bin/sh
set -eu
unbound_pid=""
tlspol_pid=""

stop_children() {
	for pid in "$tlspol_pid" "$unbound_pid"; do
		if [ -n "$pid" ]; then
			kill -TERM "$pid" 2>/dev/null || true
		fi
	done
	for pid in "$tlspol_pid" "$unbound_pid"; do
		if [ -n "$pid" ]; then
			wait "$pid" 2>/dev/null || true
		fi
	done
}

# shellcheck disable=SC2329 # Invoked by the signal trap below.
shutdown() {
	trap - TERM INT QUIT
	stop_children
	exit 0
}

# shellcheck disable=SC2329 # Invoked by the signal trap below.
reload() {
	if [ -n "$tlspol_pid" ]; then
		kill -HUP "$tlspol_pid" 2>/dev/null || true
	fi
}

trap shutdown TERM INT QUIT
trap reload HUP

# Upgrade from old container with persistent config.yaml
if [ -e /data/config.yaml ]; then
	mv /data/config.yaml /data/config.yaml.bak
	echo "WARNING: /data/config.yaml is deprecated and removed. See /etc/postfix-tlspol/config.yaml (which will be overridden on each update as it is maintained by the container)"
fi

mkdir -p /var/lib/unbound
chmod 0700 /var/lib/unbound
if [ ! -s /var/lib/unbound/trusted-key.key ]; then
	cp /etc/unbound/trusted-key.initial /var/lib/unbound/trusted-key.key
fi
chmod 0600 /var/lib/unbound/trusted-key.key

/usr/sbin/unbound -d -c /etc/unbound/unbound.conf &
unbound_pid="$!"
ready=0
for _ in $(seq 1 30); do
  if nslookup -type=SOA . 127.0.0.1:8053 >/dev/null 2>&1; then
    ready=1
    break
	fi
	if ! kill -0 "$unbound_pid" 2>/dev/null; then
		status=1
		if wait "$unbound_pid"; then
			status=1
		else
			status="$?"
		fi
		echo "ERROR: Unbound exited before becoming ready (status $status)." >&2
		exit "$status"
	fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "ERROR: Unbound started but recursive DNS did not become ready. Check container outbound DNS access." >&2
  kill "$unbound_pid" 2>/dev/null || true
  wait "$unbound_pid" 2>/dev/null || true
  exit 1
fi
cd /data
/usr/bin/postfix-tlspol -config /etc/postfix-tlspol/config.yaml &
tlspol_pid="$!"

while kill -0 "$unbound_pid" 2>/dev/null && kill -0 "$tlspol_pid" 2>/dev/null; do
	sleep 1 &
	wait "$!" || true
done

if ! kill -0 "$unbound_pid" 2>/dev/null; then
	failed_name="Unbound"
	failed_pid="$unbound_pid"
else
	failed_name="postfix-tlspol"
	failed_pid="$tlspol_pid"
fi
status=1
if wait "$failed_pid"; then
	status=1
else
	status="$?"
fi
echo "ERROR: $failed_name exited unexpectedly (status $status)." >&2
stop_children
exit "$status"
