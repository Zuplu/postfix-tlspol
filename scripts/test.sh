#!/bin/sh
cd "$(dirname "$(dirname "$(readlink -f "$0")")")"

exec go test -v -count=1 -tags netgo ./...
