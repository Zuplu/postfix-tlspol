#!/bin/sh

act="$1"

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

MAX_GOAMD64="v1"
if [ "$(uname -m)" = "x86_64" ]; then
    check_level() {
      level="$1"
      flags=$(sed -n '/^flags[[:space:]]*:/{s/^flags[[:space:]]*:[[:space:]]*//; p; q}' /proc/cpuinfo)
      shift
      for flag in "$@"; do
        found=0
        for alt in $(echo "$flag" | tr '|' ' '); do
          case "$flags" in
            *"$alt"*)
              found=1
              break
              ;;
          esac
        done
        [ "$found" -eq 0 ] && return 1
      done
      return 0
    }
    v2_flags="cx16 lahf_lm popcnt sse3 sse4_1 sse4_2 ssse3"
    v3_flags="avx avx2 bmi1 bmi2 f16c fma lzcnt|abm movbe xsave"
    v4_flags="avx512f avx512bw avx512cd avx512dq avx512vl"
    for level in v2 v3 v4; do
      eval "current_flags=\"\$${level}_flags\""
      set -- $current_flags
      if check_level "$level" "$@"; then
        MAX_GOAMD64="$level"
      fi
    done
fi

if [ -n "$TARGETPLATFORM" ]; then
    level="v1"
    case "$TARGETPLATFORM" in
      "linux/amd64/"*)
        reqLevel="$(echo "$TARGETPLATFORM" | awk -F/ '{print $NF}')"
        if [ "${reqLevel#v}" -le "${MAX_GOAMD64#v}" ]; then
            level="$reqLevel"
        else
            level="$MAX_GOAMD64"
        fi
        ;;
      *)
        ;;
    esac
    export GOAMD64="$level"
fi

if [ -z "$GOAMD64" ]; then
    export GOAMD64="$MAX_GOAMD64"
fi

# Get working directory relative to this script
BASEDIR=$(dirname "$(dirname "$(readlink -f "$0")")")
cd "$BASEDIR"

build_go() {
    mkdir -p build
    if command -v go >/dev/null 2>&1; then
        export GOTOOLCHAIN=auto
        export CGO_ENABLED=0
        go mod download
        VERSION="$(git describe --always --tags --match='v*' --abbrev=7 --dirty=-modified)"
        echo "${cyanbg}Version: $VERSION$rst"
        echo "${green}Testing basic functionality...$rst"
        # We are only doing a short test here, run scripts/test.sh for a detailed test
        if [ -n "$GITHUB_ACTIONS" ] || go test -tags netgo -failfast -short ./...; then
            echo "${green}Test succeeded.$rst"
        else
            echo "${red}Test failed.$rst"
            exit 1
        fi
        echo "${green}Building postfix-tlspol...$rst"
        if [ -n "$GOAMD64" ]; then
            echo "${cyanbg}(Optimized for x86_64-$GOAMD64)$rst"
        fi
        if go build -buildmode=exe -tags netgo -ldflags "-d -extldflags '-static' -s -X 'main.Version=$VERSION'" -o build/postfix-tlspol .; then
            echo "${green}Build succeeded!$rst"
        else
            echo "${red}Build failed!$rst"
            exit 1
        fi
        # Migrate config.yaml to new directory structure
        [ -f config.yaml ] && mv config.yaml configs/config.yaml
        # Create scripts/config.yaml from blueprint if it does not exist
        [ ! -f configs/config.yaml ] && cp -a configs/config.default.yaml configs/config.yaml
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
        sleep 0.1
        systemctl status --all --no-pager postfix-tlspol.service
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
( [ "$act" = "build-only" ] || [ -n "$GITHUB_ACTIONS" ] ) && { build_go; exit 0; }

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
