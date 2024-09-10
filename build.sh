#!/bin/sh

# Get working directory relative to this shell script
BASEDIR=$(dirname $(realpath "$0"))
cd "$BASEDIR"/src

# Build go executable
go build -ldflags '-s -w' -o ../postfix-tlspol .

cd ..

# Build and (in case the file is already linked) reload systemd service unit
if which systemctl 2> /dev/null > /dev/null; then
  sed -e "s!%%BASEDIR%%!${BASEDIR}!g" utils/postfix-tlspol.service.template > postfix-tlspol.service
  systemctl daemon-reload
fi

# Create config.yaml if it does not exist
if ! [ -f config.yaml ]; then
    cp -a config.example.yaml config.yaml
fi
