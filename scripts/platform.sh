#!/bin/sh
# Sourced by both builds. No host CPU probing when a target was supplied.
case "${TARGETPLATFORM:?Set TARGETPLATFORM explicitly}" in
  linux/amd64|linux/amd64/v1) GOARCH=amd64; GOAMD64=v1; CPU_FLAGS='-march=x86-64 -mtune=generic'; OPENSSL_TARGET=linux-x86_64 ;;
  linux/amd64/v2) GOARCH=amd64; GOAMD64=v2; CPU_FLAGS='-march=x86-64-v2 -mtune=generic'; OPENSSL_TARGET=linux-x86_64 ;;
  linux/amd64/v3) GOARCH=amd64; GOAMD64=v3; CPU_FLAGS='-march=x86-64-v3 -mtune=generic'; OPENSSL_TARGET=linux-x86_64 ;;
  linux/386) GOARCH=386; GO386=sse2; CPU_FLAGS='-march=pentium4 -mtune=generic'; OPENSSL_TARGET=linux-x86 ;;
  linux/arm/v6) GOARCH=arm; GOARM=6; CPU_FLAGS='-march=armv6zk -mfpu=vfp -mfloat-abi=hard'; OPENSSL_TARGET=linux-armv4 ;;
  linux/arm/v7) GOARCH=arm; GOARM=7; CPU_FLAGS='-march=armv7-a -mfpu=vfpv3-d16 -mfloat-abi=hard'; OPENSSL_TARGET=linux-armv4 ;;
  linux/arm64|linux/arm64/v8) GOARCH=arm64; GOARM64=v8.0; CPU_FLAGS='-march=armv8-a'; OPENSSL_TARGET=linux-aarch64 ;;
  linux/ppc64le) GOARCH=ppc64le; GOPPC64=power8; CPU_FLAGS='-mcpu=power8'; OPENSSL_TARGET=linux-ppc64le ;;
  linux/riscv64) GOARCH=riscv64; GORISCV64=rva20u64; CPU_FLAGS='-march=rv64gc -mabi=lp64d'; OPENSSL_TARGET=linux64-riscv64 ;;
  linux/s390x) GOARCH=s390x; CPU_FLAGS='-march=z196'; OPENSSL_TARGET=linux64-s390x ;;
  *) echo "Unsupported target: $TARGETPLATFORM; see scripts/platform.sh (AMD64 v4 is not supported)." >&2; exit 1 ;;
esac
GOOS=linux
export GOOS GOARCH GOAMD64 GO386 GOARM GOARM64 GOPPC64 GORISCV64 CPU_FLAGS OPENSSL_TARGET
