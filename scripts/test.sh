#!/bin/sh
# Get working directory relative to this script
BASEDIR=$(dirname "$(dirname "$(readlink -f "$0")")")
cd "$BASEDIR"
exec go test -v -count=1 ./...
