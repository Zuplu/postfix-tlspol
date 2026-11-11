ARG ALPINE_IMAGE=alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

# Verification runs on the builder, independently of the target architecture.
FROM --platform=$BUILDPLATFORM ${ALPINE_IMAGE} AS source-tools
RUN apk add --no-cache python3 gnupg
COPY .github/scripts/dependencies.py /inputs/.github/scripts/dependencies.py

# A: official precompiled Go, without a dependency on the golang Docker image.
FROM source-tools AS go-toolchain
COPY deployments/dependencies/go.json deployments/dependencies/google.asc /inputs/deployments/dependencies/
ARG BUILDARCH
RUN python3 /inputs/.github/scripts/dependencies.py fetch go --arch "$BUILDARCH" --output /tmp/go.tar.gz \
  && tar -xzf /tmp/go.tar.gz -C /usr/local && rm /tmp/go.tar.gz
ENV PATH=/usr/local/go/bin:$PATH GOTOOLCHAIN=local CGO_ENABLED=0 GOMAXPROCS=3 GOFLAGS=-p=3

FROM go-toolchain AS go-build
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor/ vendor/
COPY scripts/build.sh scripts/platform.sh scripts/
COPY configs/config.default.yaml configs/config.default.yaml
COPY main.go LICENSE ./
COPY internal/ internal/
ARG TARGETPLATFORM
ARG VERSION=0.0.0-dev
RUN PREFIX=/out NOTEST=1 scripts/build.sh build-only \
  && mkdir -p /out/usr/bin /out/usr/share/postfix-tlspol \
  && mv /out/bin/postfix-tlspol /out/usr/bin/ \
  && cp /inputs/deployments/dependencies/go.json /out/usr/share/postfix-tlspol/ \
  && rm -rf /out/bin /out/etc /out/var /root/.cache/go-build /src/build

FROM scratch AS go-artifact
COPY --from=go-build /out/usr/bin/postfix-tlspol /postfix-tlspol

# B: native sources do not depend on application files or Go inputs.
FROM source-tools AS native-sources
COPY deployments/dependencies/unbound.json deployments/dependencies/openssl.json deployments/dependencies/nlnetlabs.asc deployments/dependencies/openssl.asc /inputs/deployments/dependencies/
RUN python3 /inputs/.github/scripts/dependencies.py fetch unbound --output /sources/unbound.tar.gz \
  && python3 /inputs/.github/scripts/dependencies.py fetch openssl --output /sources/openssl.tar.gz

# QEMU compiles non-native targets. Compiler programs use the base CPU level;
# optimized AMD64 outputs are linked but never executed in this stage.
FROM ${ALPINE_IMAGE} AS unbound-build
RUN apk add --no-cache gcc binutils make \
  musl-dev fortify-headers perl \
  expat-dev linux-headers
COPY --from=native-sources /sources/openssl.tar.gz /sources/openssl.tar.gz
COPY scripts/build-unbound.sh scripts/platform.sh /inputs/scripts/
ARG TARGETPLATFORM
RUN sh /inputs/scripts/build-unbound.sh openssl
COPY --from=native-sources /sources/unbound.tar.gz /sources/unbound.tar.gz
COPY --from=native-sources /inputs/deployments/dependencies/ /inputs/deployments/dependencies/
RUN sh /inputs/scripts/build-unbound.sh unbound

# Supplement the image scanner with explicit static-library/toolchain provenance.
FROM source-tools AS dependency-sbom
COPY deployments/dependencies/*.json /inputs/deployments/dependencies/
RUN python3 /inputs/.github/scripts/dependencies.py sbom all --output /dependencies.cdx.json

# C: an explicit runtime closure from the pinned base, not its entire rootfs.
FROM ${ALPINE_IMAGE} AS runtime-files
RUN mkdir -p /rootfs/bin /rootfs/lib /rootfs/etc/ssl/certs \
    /rootfs/etc/postfix-tlspol /rootfs/etc/unbound /rootfs/data /rootfs/var/lib/unbound /rootfs/tmp \
  && cp /bin/busybox /rootfs/bin/ \
  && for app in sh nslookup wget mkdir chmod cp mv seq sleep; do ln -s busybox "/rootfs/bin/$app"; done \
  && cp -L /lib/ld-musl-*.so.1 /rootfs/lib/ \
  && for lib in /rootfs/lib/ld-musl-*.so.1; do name="${lib##*/ld-musl-}"; ln -s "${lib##*/}" "/rootfs/lib/libc.musl-$name"; done \
  && cp /etc/ssl/cert.pem /rootfs/etc/ssl/certs/ca-certificates.crt \
  && printf 'default:x:1000:1000:default:/data:/bin/sh\n' > /rootfs/etc/passwd \
  && printf 'default:x:1000:\n' > /rootfs/etc/group \
  && chmod 1777 /rootfs/tmp \
  && chown 1000:1000 /rootfs/data /rootfs/var/lib/unbound \
  && chmod 0700 /rootfs/var/lib/unbound
COPY configs/config.default.yaml /rootfs/etc/postfix-tlspol/config.yaml
COPY deployments/unbound.conf deployments/trusted-key.initial /rootfs/etc/unbound/
COPY --chmod=0755 deployments/entrypoint.sh /rootfs/entrypoint.sh
RUN sed -i -e 's/127\.0\.0\.1:8642/0.0.0.0:8642/' \
  -e 's/#address:/address:/' -e 's/127\.0\.0\.53:53/127.0.0.1:8053/' \
  -e 's!: /var/lib/postfix-tlspol/!: !' /rootfs/etc/postfix-tlspol/config.yaml \
  && chmod 0444 /rootfs/etc/unbound/trusted-key.initial \
  && chmod 0644 /rootfs/etc/postfix-tlspol/config.yaml

FROM scratch
COPY --from=runtime-files /rootfs/ /
COPY --from=go-build /out/ /
COPY --from=unbound-build /out/ /
COPY --from=dependency-sbom /dependencies.cdx.json /usr/share/postfix-tlspol/dependencies.cdx.json
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER default
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD nslookup -type=SOA . 127.0.0.1:8053 >/dev/null 2>&1 \
  && wget -q -T 3 -O /dev/null http://127.0.0.1:8642/metrics || exit 1
ENTRYPOINT ["/entrypoint.sh"]
EXPOSE 8642
