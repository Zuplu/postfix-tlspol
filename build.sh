#!/bin/sh

# Get working directory relative to this shell script
BASEDIR=$(dirname $(realpath "$0"))
cd "$BASEDIR"

build_go() {
    if which go 2> /dev/null > /dev/null; then
        cd src
        echo "Building postfix-tlspol..."
        go build -ldflags '-s -w' -o ../postfix-tlspol .
        cd ..
        echo "------------------------"
        if ! [ -f config.yaml ]; then
            echo "Copying config.yaml..."
            cp -a config.example.yaml config.yaml
            echo "------------------------"
        fi
    else
        echo "Go toolchain not found, but is required when not installing as a Docker app"
        exit 1
    fi
}

install_systemd_service() {
    build_go

    if which systemctl 2> /dev/null > /dev/null; then
        sed -e "s!%%BASEDIR%%!${BASEDIR}!g" utils/postfix-tlspol.service.template > postfix-tlspol.service
        if [ "$(systemctl is-enabled postfix-tlspol.service)" = "enabled" ]; then
            echo "Restarting service unit..."
            systemctl daemon-reload
            systemctl restart postfix-tlspol.service
        else
            echo "Enabling and starting service unit..."
            systemctl enable --now ./postfix-tlspol.service
        fi
        systemctl status --no-pager --full postfix-tlspol.service
    else
        echo "systemctl not found"
    fi
}

install_docker_app() {
    cd utils
    if which docker 2> /dev/null > /dev/null; then
        docker compose up -d
    else
        echo "Docker not found"
    fi
}

if [ "$1" = "build-only" ]; then
    build_go
    exit 0
fi

read_char() {
    old=$(stty -g)
    stty raw -echo min 0 time 100
    eval "$1=\$(dd bs=1 count=1 2>/dev/null)"
    stty $old
}

echo "Do you want to install a Docker app or a systemd service? (d/s)"
read_char choice

case "$choice" in
    d|D)
        install_docker_app
        ;;
    s|S)
        install_systemd_service
        ;;
    *)
        echo "Invalid choice. Press 'd' for Docker or 's' for systemd service. Now building only..."
        build_go
        ;;
esac
