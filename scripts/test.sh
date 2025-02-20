#!/bin/sh
BASEDIR=$(dirname "$(dirname "$(readlink -f "$0")")")
cd "$BASEDIR"
exec go test -v -count=1 ./...
