#!/bin/sh
if command -v nc >/dev/null 2>&1; then
  echo ":json $1" | nc 127.0.0.1 8642 | python -m json.tool
  exit 0
else
  echo "Install netcat for detailed evaluation.\n"
fi

if ! postmap -q "$1" socketmap:inet:127.0.0.1:8642:query ; then
  echo "Not found"
fi
