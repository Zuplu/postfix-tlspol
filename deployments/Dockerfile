FROM golang:1.24.0-alpine3.21@sha256:2d40d4fc278dad38be0777d5e2a88a2c6dee51b0b29c97a764fc6c6a11ca893c AS workspace

ARG TARGETPLATFORM
ARG GITHUB_ACTIONS

# Create a non-root user
RUN addgroup -g 1000 default \
  && adduser -G default -u 1000 default -D

# Install unbound and valkey (redis)
RUN apk add --no-cache git unbound valkey

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
  && apk --purge del git apk-tools

# Create data dir
RUN mkdir -p /data \
  && chown default:default /data

# Setup postfix-tlspol
RUN sed -i -e "s/127\.0\.0\.1:8642/0\.0\.0\.0:8642/" -e "s/127\.0\.0\.53:53/127\.0\.0\.1:8053/" /etc/postfix-tlspol/config.yaml \
  && chown -R default:default /etc/postfix-tlspol

# Setup unbound
RUN <<EOR
  chown -R default:default /usr/share/dnssec-root
  cat <<EOF > /etc/unbound/unbound.conf
server:
  username: default
  chroot: ""
  do-daemonize: yes
  use-syslog: no
  verbosity: 1
  logfile: /var/log/unbound.log
  log-servfail: yes
  ede: yes
  interface: 127.0.0.1
  port: 8053
  do-ip4: yes
  prefer-ip4: yes
  do-ip6: yes
  prefer-ip6: no
  do-udp: yes
  do-tcp: yes
  max-udp-size: 1232
  edns-buffer-size: 1232
  auto-trust-anchor-file: /usr/share/dnssec-root/trusted-key.key
  cache-min-ttl: 10
  cache-max-ttl: 240
  serve-original-ttl: yes
  serve-expired: no
  prefetch-key: yes
  prefetch: yes
  hide-identity: yes
  hide-version: yes
  target-fetch-policy: "4 3 2 2 1"
  harden-glue: yes
  harden-dnssec-stripped: yes
  harden-algo-downgrade: yes
  harden-below-nxdomain: no
  harden-referral-path: no
  harden-large-queries: no
  harden-short-bufsize: yes
  harden-unverified-glue: no
  harden-unknown-additional: no
  aggressive-nsec: no
  val-permissive-mode: no
  unknown-server-time-limit: 1500
  jostle-timeout: 1000
  discard-timeout: 4000
  so-reuseport: yes
  num-threads: 2
  qname-minimisation: no
  minimal-responses: yes
  infra-cache-min-rtt: 4500
  infra-keep-probing: yes
  module-config: "validator iterator"
remote-control:
  control-enable: no
EOF
  chown -R default:default /etc/unbound
  touch /var/log/unbound.log
  chown default:default /var/log/unbound.log
EOR

# Setup valkey (redis)
RUN <<EOR
  mkdir -p /etc/valkey
  cat <<EOF > /etc/valkey/valkey.conf
bind 127.0.0.1 -::1
port 6379
daemonize yes
pidfile /dev/null
logfile /var/log/valkey.log
loglevel notice
dbfilename cache.rdb
dir /data
EOF
  chown -R default:default /etc/valkey
  touch /var/log/valkey.log
  chown default:default /var/log/valkey.log
EOR

# Setup entrypoint
RUN <<EOR
  cat <<EOF > /entrypoint.sh
#!/bin/sh
set -e
# Upgrade from old container with persistent config.yaml
if [ -e /data/config.yaml ]; then
  mv /data/config.yaml /data/config.yaml.bak
  echo "WARNING: /data/config.yaml is deprecated and removed. See /etc/postfix-tlspol/config.yaml (which will be overriden on each update as it is maintained by the container)"
fi
truncate -s0 /var/log/unbound.log /var/log/valkey.log
( cd /etc/unbound ; \
  /usr/sbin/unbound -c /etc/unbound/unbound.conf ) &
( cd /data ; \
  /usr/bin/valkey-server /etc/valkey/valkey.conf ) &
wait
tail -f /var/log/unbound.log &
tail -f /var/log/valkey.log &
exec /usr/bin/postfix-tlspol -config /etc/postfix-tlspol/config.yaml
EOF
  chmod +x /entrypoint.sh
EOR

# Squash layers
FROM scratch
COPY --from=workspace / /

USER default

ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 8642
