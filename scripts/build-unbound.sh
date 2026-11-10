#!/bin/sh
set -eu
# shellcheck source=/dev/null
. /inputs/scripts/platform.sh
export CFLAGS="-O3 -flto $CPU_FLAGS -fstack-protector-strong -D_FORTIFY_SOURCE=2"
export LDFLAGS='-flto -Wl,-z,relro,-z,now'
export AR=gcc-ar RANLIB=gcc-ranlib
export SOURCE_DATE_EPOCH=0
export MAKEFLAGS=-j3
component="${1:?Choose openssl or unbound}"
trap 'echo "$component build failed for $TARGETPLATFORM; see the preceding compiler/configure diagnostic." >&2' EXIT
printf 'Building %s for %s\n' "$component" "$TARGETPLATFORM"

mkdir -p /out/usr/sbin /out/usr/share/postfix-tlspol
if [ "$component" = openssl ]; then
  # Keep native code alongside LTO IR for cheap configure feature probes.
  export CFLAGS="$CFLAGS -ffat-lto-objects"
  mkdir -p /work/openssl /native
  tar -xzf /sources/openssl.tar.gz -C /work/openssl --strip-components=1
  cd /work/openssl
  # Configure never executes target code. Keep assembly and runtime CPU dispatch.
  ./Configure "$OPENSSL_TARGET" --prefix=/native --libdir=lib \
    no-shared no-tests no-apps no-docs no-module no-legacy
  make build_libs
  make install_dev
  cp LICENSE.txt /out/usr/share/postfix-tlspol/LICENSE.OpenSSL
  rm -rf /work
  trap - EXIT
  exit 0
fi
[ "$component" = unbound ] || exit 1
mkdir -p /work/unbound
tar -xzf /sources/unbound.tar.gz -C /work/unbound --strip-components=1

cd /work/unbound
# Distinct triplets force cross mode. Never execute v2/v3 configure probes.
triplet="$(cc -dumpmachine)"
cpu="${triplet%%-*}"
build_cflags="$CFLAGS -fPIE -pthread"
build_ldflags="$LDFLAGS -pie -L/native/lib"
# Probe the fat archives without repeating whole-library LTO for every symbol.
CC=cc CFLAGS="$build_cflags -fno-lto" LDFLAGS="$build_ldflags -fno-lto" \
  ./configure --build="$cpu-build-linux-musl" --host="$triplet" \
  --prefix=/usr --sysconfdir=/etc --with-conf-file=/etc/unbound/unbound.conf \
  --with-pidfile= --with-rootkey-file=/var/lib/unbound/trusted-key.key \
  --with-ssl=/native --with-libevent=no --with-pthreads \
  --without-pythonmodule --without-pyunbound --without-libnghttp2 \
  --without-libngtcp2 --disable-shared --enable-flto --disable-rpath \
  --enable-pie --enable-relro-now
# Configure requires Expat headers; only the unused unbound-anchor links Expat.
make CFLAGS="$build_cflags" LDFLAGS="$build_ldflags" unbound unbound-checkconf
install -m 0755 unbound unbound-checkconf /out/usr/sbin/
strip /out/usr/sbin/unbound /out/usr/sbin/unbound-checkconf
# Assert the runtime closure without executing any target binaries.
for binary in /out/usr/sbin/*; do
  readelf -h "$binary" | grep -Eq 'Type:.*DYN' || { echo "Expected PIE: $binary" >&2; exit 1; }
  readelf -l "$binary" | grep -q GNU_RELRO || { echo "Missing RELRO: $binary" >&2; exit 1; }
  readelf -d "$binary" | sed -n 's/.*Shared library: \[\(.*\)\].*/\1/p' |
    while read -r library; do
      case "$library" in
        libc.musl-*.so.1) ;;
        *) echo "Unexpected runtime dependency for $TARGETPLATFORM: $library" >&2; exit 1 ;;
      esac
    done
done
cp /inputs/deployments/dependencies/openssl.json /inputs/deployments/dependencies/unbound.json /out/usr/share/postfix-tlspol/
cp /work/unbound/LICENSE /out/usr/share/postfix-tlspol/LICENSE.Unbound
apk info -v | sort > /out/usr/share/postfix-tlspol/native-build-packages.txt
# Remove disposable compilation trees only after successful artifact assembly.
rm -rf /work /native
trap - EXIT
