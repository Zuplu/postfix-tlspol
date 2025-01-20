#!/bin/sh

# Define color codes
red=$(tput setaf 1)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
cyanbg=$(tput setaf 0)$(tput setab 6)
rst=$(tput sgr0)

# Get working directory relative to this script
BASEDIR=$(dirname "$(readlink -f "$0")")
cd "$BASEDIR"

build_go() {
    if command -v go >/dev/null 2>&1; then
        cd src || exit
        echo "${green}Building postfix-tlspol...${rst}"
        VERSION=$(git describe --tags --always --long --abbrev=7 --dirty=-modified)
        echo "${cyanbg}Version: ${VERSION}${rst}"
        if go build -ldflags "-s -w -X 'main.VERSION=${VERSION}'" -o ../postfix-tlspol .; then
            echo "${green}Build succeeded!${rst}"
        else
            echo "${red}Build failed!${rst}"
            exit 1
        fi
        cd ..
        [ ! -f config.yaml ] && cp -a config.example.yaml config.yaml
    else
        echo "${red}Go toolchain not found. Required unless installing as a Docker container.${rst}"
        exit 1
    fi
}

install_systemd_service() {
    build_go
    if command -v systemctl >/dev/null 2>&1; then
        sed "s!%%BASEDIR%%!${BASEDIR}!g" utils/postfix-tlspol.service.template > postfix-tlspol.service
        if systemctl is-enabled postfix-tlspol.service >/dev/null 2>&1; then
            echo "Restarting service unit..."
            systemctl daemon-reload
            systemctl restart postfix-tlspol.service
        else
            echo "Enabling and starting service unit..."
            systemctl enable --now ./postfix-tlspol.service
        fi
        systemctl status --no-pager --full postfix-tlspol.service
    else
        echo "${red}systemctl not found.${rst}"
    fi
}

install_docker_app() {
    cd utils || exit
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
