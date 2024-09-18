#!/bin/bash

# Get working directory relative to this shell script
BASEDIR=$(dirname $(realpath "$0"))
cd "$BASEDIR"

install_systemd_service() {

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

while true; do
    echo "Do you want to install a Docker app or a systemd service? (d/s)"
    read -n 1 choice
    echo ""
    case "$choice" in
        d|D)
            install_docker_app
            break
            ;;
        s|S)
            install_systemd_service
            break
            ;;
        *)
            echo "Invalid choice. Please enter 'd' for Docker app or 's' for systemd service."
            ;;
    esac
done
