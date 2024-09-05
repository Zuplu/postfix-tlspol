#!/bin/sh
if ! postmap -q "$1" socketmap:inet:127.0.0.1:8642:query ; then
  echo "Not found"
fi
