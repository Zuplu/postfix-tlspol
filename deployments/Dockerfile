FROM golang:1-alpine AS workspace

# Create a non-root user
RUN addgroup -g 1000 default \
  && adduser -G default -u 1000 default -D

# Install unbound and redis
RUN apk add --no-cache unbound redis git

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
RUN su default -c 'sed -i -e "s/127\.0\.0\.1:8642/0\.0\.0\.0:8642/" -e "s/prefetch: no/prefetch: yes/" /build/configs/config.yaml' \
  && mv /build/build/postfix-tlspol / \
  && mv /build/configs/config.yaml /data/ \
  && rm -rf /build

# Setup unbound
RUN chown -R default:default /usr/share/dnssec-root \
  && chmod 4755 /usr/sbin/unbound \
  && echo -e "server:\n  username: default\n  chroot: \"\"\n  do-daemonize: no\n  use-syslog: no\n  verbosity: 1\n  interface: 127.0.0.53\n  auto-trust-anchor-file: /usr/share/dnssec-root/trusted-key.key\n  cache-min-ttl: 10\n  cache-max-ttl: 180\n  serve-original-ttl: yes" > /etc/unbound/unbound.conf \
  && chown -R default:default /etc/unbound

# Setup redis
RUN echo -e "bind 127.0.0.1 -::1\nport 6379\ndaemonize no\nlogfile \"\"\nloglevel notice\ndbfilename cache.rdb\ndir /data" > /etc/redis.conf

# Setup entrypoint
RUN echo -e "#!/bin/sh\n( cd /data ; /usr/bin/redis-server /etc/redis.conf ) &\n( cd /etc/unbound ; /usr/sbin/unbound -c /etc/unbound/unbound.conf ) &\nexec /postfix-tlspol /data/config.yaml" > /entrypoint.sh && chmod +x /entrypoint.sh

# Squash layers
FROM scratch
COPY --from=workspace / /

USER default

ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 8642
