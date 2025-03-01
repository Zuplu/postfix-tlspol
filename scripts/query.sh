#!/bin/sh

if [ -z "$1" ]; then
  echo "Usage: $0 [domain]"
  exit 1
fi

if [ ! -f /usr/bin/postfix-tlspol ]; then
  echo "Build and start postfix-tlspol first."
  exit 1
fi

printf "Tip: Use \033[34mpostfix-tlspol [-config /etc/postfix-tlspol/config.yaml] -query $1\033[0m instead.\n" >&2
exec /usr/bin/postfix-tlspol -query "$1"
