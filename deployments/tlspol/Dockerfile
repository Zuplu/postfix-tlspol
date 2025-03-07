FROM golang:1.24.1-alpine3.21@sha256:43c094ad24b6ac0546c62193baeb3e6e49ce14d3250845d166c77c25f64b0386 AS workspace

ARG TARGETPLATFORM
ARG GITHUB_ACTIONS

# Create a non-root user
RUN addgroup -g 1000 default \
  && adduser -G default -u 1000 default -D

RUN apk add --no-cache git

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
RUN sed -i -e "s/127\.0\.0\.1:8642/0\.0\.0\.0:8642/" -e "s/127\.0\.0\.53:53/unbound-tlspol:53/" -e "s/127\.0\.0\.1:6379/valkey-tlspol:6379/" /etc/postfix-tlspol/config.yaml \
  && chown -R default:default /etc/postfix-tlspol

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
exec /usr/bin/postfix-tlspol -config /etc/postfix-tlspol/config.yaml
EOF
  chmod +x /entrypoint.sh
EOR

# Squash layers
FROM alpine:3.21 AS final
COPY --from=workspace /usr/bin/postfix-tlspol /usr/bin/postfix-tlspol
COPY --from=workspace /etc/postfix-tlspol/config.yaml /etc/postfix-tlspol/config.yaml
COPY --from=workspace /entrypoint.sh /entrypoint.sh
RUN apk add netcat-openbsd \
  && addgroup -g 1000 default \
  && adduser -G default -u 1000 default -D \
  && chown default:default /entrypoint.sh \
  && chmod 0500 /entrypoint.sh


HEALTHCHECK --interval=10s --timeout=2s \
  CMD nc -z 127.0.0.1 8642 || exit 1

USER default

ENTRYPOINT ["/bin/sh", "-c"]
CMD ["/entrypoint.sh"]

EXPOSE 8642
