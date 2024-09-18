FROM alpine:3.20 AS workspace

# Install unbound and redis
RUN apk add --no-cache unbound redis

# Download and unpack Go toolchain
RUN apk add --no-cache wget \
  && export ARCH=$(arch | sed -e 's/aarch64/arm64/' -e 's/x86_64/amd64/') \
  && wget https://go.dev/dl/go1.23.1.linux-$ARCH.tar.gz -O /go.tar.gz \
  && tar -C /usr/local -xzf /go.tar.gz \
  && rm -f /go.tar.gz \
  && apk del wget

# Copy postfix-tlspol
COPY . /postfix-tlspol

# Build postfix-tlspol and remove Go toolchain
RUN PATH="$PATH:/usr/local/go/bin" /postfix-tlspol/build.sh build-only \
  && /usr/local/go/bin/go clean -cache -modcache \
  && rm -rf /usr/local/go

# Configure postfix-tlspol
RUN sed -i -e "s/127\.0\.0\.1:8642/0\.0\.0\.0:8642/" -e "s/prefetch: no/prefetch: yes/" /postfix-tlspol/config.yaml

# Setup unbound
RUN chmod a+rwx /usr/share/dnssec-root \
  && echo -e "server:\n  do-daemonize: no\n  use-syslog: no\n  verbosity: 1\n  interface: 127.0.0.53\n  auto-trust-anchor-file: /usr/share/dnssec-root/trusted-key.key\n  cache-min-ttl: 10\n  cache-max-ttl: 180\n  serve-original-ttl: yes\n  serve-expired: no" > /etc/unbound/unbound.conf

# Setup entrypoint
RUN echo -e "#!/bin/sh\nexport PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"\nredis-server &\nunbound -c /etc/unbound/unbound.conf &\nexec /postfix-tlspol/postfix-tlspol /postfix-tlspol/config.yaml" > /entrypoint.sh && chmod +x /entrypoint.sh

# Squash layers
FROM scratch
COPY --from=workspace / /

ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 8642
