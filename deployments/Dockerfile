FROM golang:alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS workspace

ARG TARGETPLATFORM
ARG GITHUB_ACTIONS
ARG VERSION=0.0.0-dev

# Create a non-root user
RUN addgroup -g 1000 default \
  && adduser -G default -u 1000 default -D

# Install unbound
RUN apk add --no-cache unbound

# Copy postfix-tlspol
COPY . /build

# Build postfix-tlspol
RUN /build/scripts/build.sh build-only

# Remove residual toolchain
RUN go clean -cache -modcache \
  && rm -rf /build \
  && rm -rf /usr/local/go \
  && rm -rf /go \
  && rm -rf /home \
  && apk --purge del apk-tools

# Create data dir
RUN mkdir -p /data \
  && chown -R default:default /data

# Setup postfix-tlspol
RUN sed -i -e "s/127\.0\.0\.1:8642/0\.0\.0\.0:8642/" \
  -e "s/#address:/address:/" \
  -e "s/127\.0\.0\.53:53/127\.0\.0\.1:8053/" \
  -e "s!: /var/lib/postfix-tlspol/!: !" \
  /etc/postfix-tlspol/config.yaml \
  && chown -R root:root /etc/postfix-tlspol \
  && chmod 0644 /etc/postfix-tlspol/config.yaml

# Setup unbound
RUN <<EOR
  cp /usr/share/dnssec-root/trusted-key.key /etc/unbound/trusted-key.initial
  mkdir -p /var/lib/unbound
  cp /usr/share/dnssec-root/trusted-key.key /var/lib/unbound/trusted-key.key
  cat <<EOF > /etc/unbound/unbound.conf
server:
  username: ""
  chroot: ""
  do-daemonize: no
  use-syslog: no
  verbosity: 1
  logfile: ""
  log-servfail: yes
  ede: yes
  interface: 127.0.0.1
  port: 8053
  do-not-query-localhost: yes
  do-ip4: yes
  prefer-ip4: yes
  do-ip6: yes
  prefer-ip6: no
  do-udp: yes
  do-tcp: yes
  udp-connect: yes
  max-udp-size: 1232
  edns-buffer-size: 1232
  auto-trust-anchor-file: /var/lib/unbound/trusted-key.key
  msg-cache-size: 16m
  rrset-cache-size: 32m
  cache-min-ttl: 10
  cache-max-ttl: 240
  cache-max-negative-ttl: 240
  # Preserve authoritative reply TTLs while the resolver cache still expires at cache-max-ttl.
  serve-original-ttl: yes
  serve-expired: no
  prefetch-key: yes
  prefetch: yes
  hide-identity: yes
  hide-version: yes
  hide-trustanchor: yes
  target-fetch-policy: "3 2 1 0 0"
  harden-glue: yes
  harden-dnssec-stripped: yes
  harden-algo-downgrade: no
  harden-below-nxdomain: yes
  harden-referral-path: no
  harden-large-queries: no
  harden-short-bufsize: yes
  harden-unverified-glue: no
  harden-unknown-additional: no
  aggressive-nsec: yes
  val-clean-additional: yes
  val-permissive-mode: no
  unknown-server-time-limit: 376
  jostle-timeout: 200
  discard-timeout: 1900
  so-reuseport: yes
  num-threads: 2
  qname-minimisation: yes
  minimal-responses: yes
  infra-cache-min-rtt: 50
  infra-keep-probing: yes
  module-config: "validator iterator"
remote-control:
  control-enable: no
EOF
  chown -R root:root /etc/unbound
  chmod 0444 /etc/unbound/trusted-key.initial
  chown -R default:default /var/lib/unbound
  chmod 0700 /var/lib/unbound
  chmod 0600 /var/lib/unbound/trusted-key.key
  /usr/sbin/unbound-checkconf /etc/unbound/unbound.conf
EOR

# Setup entrypoint
RUN <<EOR
  cat <<EOF > /entrypoint.sh
#!/bin/sh
set -eu
unbound_pid=""
tlspol_pid=""

stop_children() {
	for pid in "\$tlspol_pid" "\$unbound_pid"; do
		if [ -n "\$pid" ]; then
			kill -TERM "\$pid" 2>/dev/null || true
		fi
	done
	for pid in "\$tlspol_pid" "\$unbound_pid"; do
		if [ -n "\$pid" ]; then
			wait "\$pid" 2>/dev/null || true
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
	if [ -n "\$tlspol_pid" ]; then
		kill -HUP "\$tlspol_pid" 2>/dev/null || true
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
unbound_pid="\$!"
ready=0
for _ in \$(seq 1 30); do
  if nslookup -type=SOA . 127.0.0.1:8053 >/dev/null 2>&1; then
    ready=1
    break
	fi
	if ! kill -0 "\$unbound_pid" 2>/dev/null; then
		status=1
		if wait "\$unbound_pid"; then
			status=1
		else
			status="\$?"
		fi
		echo "ERROR: Unbound exited before becoming ready (status \$status)." >&2
		exit "\$status"
	fi
  sleep 1
done
if [ "\$ready" -ne 1 ]; then
  echo "ERROR: Unbound started but recursive DNS did not become ready. Check container outbound DNS access." >&2
  kill "\$unbound_pid" 2>/dev/null || true
  wait "\$unbound_pid" 2>/dev/null || true
  exit 1
fi
cd /data
/usr/bin/postfix-tlspol -config /etc/postfix-tlspol/config.yaml &
tlspol_pid="\$!"

while kill -0 "\$unbound_pid" 2>/dev/null && kill -0 "\$tlspol_pid" 2>/dev/null; do
	sleep 1 &
	wait "\$!" || true
done

if ! kill -0 "\$unbound_pid" 2>/dev/null; then
	failed_name="Unbound"
	failed_pid="\$unbound_pid"
else
	failed_name="postfix-tlspol"
	failed_pid="\$tlspol_pid"
fi
status=1
if wait "\$failed_pid"; then
	status=1
else
	status="\$?"
fi
echo "ERROR: \$failed_name exited unexpectedly (status \$status)." >&2
stop_children
exit "\$status"
EOF
  chmod +x /entrypoint.sh
EOR

# Squash layers
FROM scratch
COPY --from=workspace / /

USER default

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD nslookup -type=SOA . 127.0.0.1:8053 >/dev/null 2>&1 \
  && wget -q -T 3 -O /dev/null http://127.0.0.1:8642/metrics \
  || exit 1

ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 8642
