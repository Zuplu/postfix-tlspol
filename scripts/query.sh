#!/bin/sh

if [ -z "$1" ]; then
  echo "Usage: $0 [domain]"
  exit 1
fi

BASEDIR=$(dirname "$(dirname "$(readlink -f "$0")")")
EXEPATH="$BASEDIR/build/postfix-tlspol"

if [ ! -f "$EXEPATH" ]; then
  echo "Build and start postfix-tlspol first."
  exit 1
fi

exec "$EXEPATH" -config "$BASEDIR/configs/config.yaml" -query "$1"
