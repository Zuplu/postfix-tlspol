#!/bin/sh

# Get working directory relative to this shell script
BASEDIR=$(dirname $(realpath "$0"))
cd $BASEDIR/src

# Build go executable
go build -ldflags '-s -w' -o $BASEDIR/postfix-tlspol .

# Build and (in case the file is already linked) reload systemd service unit
sed -e "s!%%BASEDIR%%!${BASEDIR}!g" ../utils/postfix-tlspol.service.template > ../postfix-tlspol.service
systemctl daemon-reload
