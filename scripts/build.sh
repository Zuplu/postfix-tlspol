#!/bin/sh

# Define color codes
red="\033[31m"
green="\033[32m"
yellow="\033[33m"
cyanbg="\033[30m\033[46m"
rst="\033[0m"

# Get working directory relative to this script
BASEDIR=$(dirname "$(dirname "$(readlink -f "$0")")")
cd "$BASEDIR"

build_go() {
    mkdir -p build
    if command -v go >/dev/null 2>&1; then
        echo "${green}Building postfix-tlspol...${rst}"
        VERSION=$(git describe --tags --always --long --abbrev=7 --dirty=-modified)
        echo "${cyanbg}Version: ${VERSION}${rst}"
        if go build -tags netgo -ldflags "-d -extldflags '-static' -s -w -X 'main.VERSION=${VERSION}'" -o build/postfix-tlspol ./internal; then
            echo "${green}Build succeeded!${rst}"
        else
            echo "${red}Build failed!${rst}"
            exit 1
        fi
        [ -f config.yaml ] && mv config.yaml configs/config.yaml
        [ ! -f configs/config.yaml ] && cp -a configs/config.example.yaml configs/config.yaml
    else
        echo "${red}Go toolchain not found. Required unless installing as a Docker container.${rst}"
        exit 1
    fi
}

install_systemd_service() {
    build_go
    if command -v systemctl >/dev/null 2>&1; then
        [ -f postfix-tlspol.service ] && rm postfix-tlspol.service
        sed "s!%%BASEDIR%%!${BASEDIR}!g" init/postfix-tlspol.service.template > init/postfix-tlspol.service
        if systemctl is-enabled postfix-tlspol.service >/dev/null 2>&1; then
            systemctl daemon-reload
            echo "Restarting service unit..."
            if systemctl is-active --quiet postfix-tlspol.service >/dev/null 2>&1; then
                systemctl stop postfix-tlspol.service
            fi
            systemctl disable postfix-tlspol.service
        else
            echo "Enabling and starting service unit..."
        fi
        systemctl enable init/postfix-tlspol.service
        systemctl daemon-reload
        systemctl start postfix-tlspol.service
        systemctl status --no-pager --full postfix-tlspol.service
    else
        echo "${red}systemctl not found.${rst}"
    fi
}

install_docker_app() {
    cd deployments || exit
    if command -v docker >/dev/null 2>&1; then
        docker compose up --build -d
    else
        echo "${red}Docker not found.${rst}"
    fi
}

# Handle "build-only" argument
[ "$1" = "build-only" ] && { build_go; exit 0; }

read_char() {
    old_stty=$(stty -g)
    stty raw -echo min 0 time 100
    eval "$1=$(dd bs=1 count=1 2>/dev/null)"
    stty "$old_stty"
}

echo "Do you want to install a Docker app or a systemd service? (d/s)"
read_char choice

case "${choice}" in
    [dD])
        install_docker_app
        ;;
    [sS])
        install_systemd_service
        ;;
    *)
        echo "${yellow}Invalid choice. Press 'd' for Docker or 's' for systemd service. Now building only...${rst}"
        build_go
        ;;
esac
