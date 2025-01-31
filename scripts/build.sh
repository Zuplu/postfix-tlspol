#!/bin/sh

# Define color codes if output is terminal
if [ -t 1 ]; then
    red="\033[31m"
    green="\033[32m"
    yellow="\033[33m"
    cyanbg="\033[30m\033[46m"
    rst="\033[0m"
else
    red=""
    green=""
    yellow=""
    cyanbg=""
    rst=""
fi

# Get working directory relative to this script
BASEDIR=$(dirname "$(dirname "$(readlink -f "$0")")")
cd "$BASEDIR"

build_go() {
    mkdir -p build
    if command -v go >/dev/null 2>&1; then
        echo "${green}Testing basic functionality...$rst"
        # We are only doing a short test here, run scripts/test.sh for a detailed test
        if go test -short ./internal; then
            echo "${green}Test succeeded.$rst"
        else
            echo "${red}Test failed.$rst"
            exit 1
        fi
        echo "${green}Building postfix-tlspol...$rst"
        VERSION=$(git describe --tags --always --long --abbrev=7 --dirty=-modified)
        echo "${cyanbg}Version: ${VERSION}$rst"
        if go build -tags netgo -ldflags "-d -extldflags '-static' -s -w -X 'main.VERSION=${VERSION}'" -o build/postfix-tlspol ./internal; then
            echo "${green}Build succeeded!$rst"
        else
            echo "${red}Build failed!$rst"
            exit 1
        fi
        # Migrate config.yaml to new directory structure
        [ -f config.yaml ] && mv config.yaml configs/config.yaml
        # Create scripts/config.yaml from blueprint if it does not exist
        [ ! -f configs/config.yaml ] && cp -a configs/config.example.yaml configs/config.yaml
    else
        echo "${red}Go toolchain not found. Required unless installing as a Docker container.$rst"
        exit 1
    fi
}

install_systemd_service() {
    build_go
    if command -v systemctl >/dev/null 2>&1; then
        # Remove systemd service unit from project root (migration from old directory structure)
        [ -f postfix-tlspol.service ] && rm postfix-tlspol.service
        sed "s!%%BASEDIR%%!$BASEDIR!g" init/postfix-tlspol.service.template > init/postfix-tlspol.service
        systemctl daemon-reload
        if systemctl is-enabled postfix-tlspol.service >/dev/null 2>&1; then
            echo "Restarting service unit...$yellow"
            systemctl reenable --now init/postfix-tlspol.service
        else
            echo "Enabling and starting service unit...$yellow"
            systemctl enable --now init/postfix-tlspol.service
        fi
        echo "$rst"
        sleep 0.2
        systemctl status -ocat --no-pager postfix-tlspol.service
    else
        echo "${red}systemctl not found.$rst"
    fi
}

install_docker_app() {
    cd deployments || exit
    if command -v docker >/dev/null 2>&1; then
        docker compose up --build -d
    else
        echo "$redDocker not found.$rst"
    fi
}

# Handle "build-only" argument and automated builds
( [ "$1" = "build-only" ] || [ -n "$GITHUB_ACTIONS" ] ) && { build_go; exit 0; }

read_char() {
    if command -v whiptail >/dev/null 2>&1; then
        eval "$1=$(whiptail --radiolist 'Please select installation method.\nNote that both are compiled from source.\nCheck the README on how to download prebuilt docker images.' 0 0 0 's' 'systemd service unit' 1 'd' 'Docker container' 0 3>&1 1>&2 2>&3)"
    else
        echo "Do you want to install a Docker container or a systemd service? Both a compiled from source. (d/s)"
        old_stty=$(stty -g)
        stty raw -echo min 0 time 150
        eval "$1=$(dd bs=1 count=1 2>/dev/null)"
        stty "$old_stty"
    fi
}

read_char choice

case "$choice" in
    [dD])
        install_docker_app
        ;;
    [sS])
        install_systemd_service
        ;;
    *)
        exit 1
        ;;
esac
