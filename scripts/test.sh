#!/bin/sh

set -eu

if [ -t 1 ]; then
  red="\033[31m"
  green="\033[32m"
  rst="\033[0m"
else
  red=""
  green=""
  rst=""
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v go > /dev/null 2>&1; then
  printf "%b\n" "${red}Go toolchain not found.${rst}" >&2
  exit 1
fi

export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

set +e
go test -v -count=1 -tags netgo ./...
rc=$?
set -e

if [ "$rc" -eq 0 ]; then
  printf "%b\n" "${green}All tests passed.${rst}"
else
  printf "%b\n" "${red}Test failed.${rst}" >&2
fi

exit "$rc"
