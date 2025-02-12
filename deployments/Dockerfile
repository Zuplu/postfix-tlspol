FROM golang:1-alpine AS workspace

# Create a non-root user
RUN addgroup -g 1000 default \
  && adduser -G default -u 1000 default -D

# Install unbound and redis
RUN apk add --no-cache git unbound redis

# Copy postfix-tlspol
COPY --chown=default:default . /build

# Build postfix-tlspol and remove Go toolchain
RUN su default -c "/build/scripts/build.sh build-only ; go clean -cache -modcache" \
  && rm -rf /usr/local/go \
  && rm -rf /go \
  && rm -rf /home \
  && apk --purge del git apk-tools

# Create data dir
RUN mkdir -p /data \
  && chown default:default /data

# Setup postfix-tlspol
RUN su default -c 'sed -i -e "s/127\.0\.0\.1:8642/0\.0\.0\.0:8642/" /build/configs/config.yaml' \
  && mv /build/build/postfix-tlspol / \
  && mv /build/configs/config.yaml /data/ \
  && rm -rf /build

# Setup unbound
RUN <<EOR
  chown -R default:default /usr/share/dnssec-root
  chmod 4755 /usr/sbin/unbound
  cat <<EOF > /etc/unbound/unbound.conf
server:
  username: default
  chroot: ""
  do-daemonize: no
  use-syslog: no
  verbosity: 1
  log-servfail: yes
  ede: yes
  interface: 127.0.0.53
  auto-trust-anchor-file: /usr/share/dnssec-root/trusted-key.key
  cache-min-ttl: 10
  cache-max-ttl: 180
  serve-original-ttl: yes
  prefetch-key: yes
  prefetch: yes
  discard-timeout: 4500
  hide-identity: yes
  hide-version: yes
  target-fetch-policy: "-1 -1 -1 -1 -1"
  harden-short-bufsize: yes
  harden-glue: yes
  harden-unverified-glue: yes
  harden-referral-path: yes
  harden-dnssec-stripped: yes
  harden-algo-downgrade: yes
  harden-below-nxdomain: yes
  aggressive-nsec: yes
  qname-minimisation: yes
  infra-keep-probing: yes
  ignore-cd-flag: yes
  module-config: "validator iterator"
EOF
  chown -R default:default /etc/unbound
EOR

# Setup redis
RUN <<EOR
  cat <<EOF > /etc/redis.conf
bind 127.0.0.1 -::1
port 6379
daemonize no
logfile ""
loglevel notice
dbfilename cache.rdb
dir /data
EOF
EOR

# Setup entrypoint
RUN <<EOR
  cat <<EOF > /entrypoint.sh
#!/bin/sh
/usr/sbin/unbound -V
/usr/bin/redis-server -v
( cd /etc/unbound ; /usr/sbin/unbound -c /etc/unbound/unbound.conf ) &
( cd /data ; /usr/bin/redis-server /etc/redis.conf ) &
exec /postfix-tlspol -config /data/config.yaml
EOF
  chmod +x /entrypoint.sh
EOR

# Squash layers
FROM scratch
COPY --from=workspace / /

USER default

ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 8642
