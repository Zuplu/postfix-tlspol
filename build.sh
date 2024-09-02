#!/bin/sh
exec go build -ldflags '-s -w' postfix-tlspol.go
