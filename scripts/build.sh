#!/bin/sh
###################
#
#  MIT License
#  Copyright (c) 2024-2025 Zuplu
#
#  Calling this script with the env variable NOOPT=1
#  will build a more compatible binary ("NOOPT=1 scripts/build.sh")
#  (i. e. Go toolchain will build for x86_64-v1
#  even if current machine supports v4)
#
#  Set env NOTEST=1 to skip testing (which requires internet access)
#
###################

act="$1"
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
if [ -n "$GITHUB_ACTIONS" ]; then
  NOTEST="${NOTEST:-1}"
fi

if [ -z "$NOOPT" ]; then
  if [ "$(uname -m)" = "x86_64" ]; then
    MAX_GOAMD64="v1"
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
        *) ;;

      esac
      export GOAMD64="$level"
    fi
    if [ -z "$GOAMD64" ]; then
      export GOAMD64="$MAX_GOAMD64"
    fi
  fi
fi

cd "$(dirname "$(dirname "$(readlink -f "$0")")")"

build_go() {
  mkdir -p build
  if command -v go > /dev/null 2>&1; then
    export GOTOOLCHAIN=auto
    export CGO_ENABLED=0
    VERSION="$(git describe --always --tags --match='v*' --abbrev=7 --dirty=-modified)"
    printf "${cyanbg}Version: $VERSION$rst\n"
    printf "${green}Testing basic functionality...$rst\n"
    # We are only doing a short test here, run scripts/test.sh for a detailed test
    if [ -n "$NOTEST" ]; then
      printf "${yellow}Test skipped.$rst\n"
    else
      if go test -tags netgo -failfast -short ./...; then
        printf "${green}Test succeeded.$rst\n"
      else
        printf "${red}Test failed.$rst\n"
        exit 1
      fi
    fi
    printf "${green}Building postfix-tlspol...$rst\n"
    if [ -n "$GOAMD64" ]; then
      printf "${cyanbg}(Optimized for x86_64-$GOAMD64)$rst\n"
    fi
    if go build -buildmode=exe -tags netgo -ldflags "-d -extldflags '-static' -s -X 'main.Version=$VERSION'" -o build/postfix-tlspol .; then
      printf "${green}Build succeeded!$rst\n"
    else
      printf "${red}Build failed!$rst\n"
      exit 1
    fi
    if [ ! -f /etc/postfix-tlspol/config.yaml ]; then
      if [ -f config.yaml ]; then
        # Migrate config.yaml to new directory structure
        mv config.yaml configs/config.yaml
      elif [ ! -f configs/config.yaml ]; then
        # Create scripts/config.yaml from blueprint if it does not exist
        cp -a configs/config.default.yaml configs/config.yaml
      fi
      install -D -m 0644 configs/config.yaml /etc/postfix-tlspol/config.yaml
      rm -f configs/config.yaml
    fi
    install -m 0755 build/postfix-tlspol /usr/bin/postfix-tlspol
  else
    printf "${red}Go toolchain not found. Required unless installing as a Docker container.$rst\n"
    exit 1
  fi
}

install_systemd_service() {
  build_go
  if command -v systemctl > /dev/null 2>&1; then
    install -D -m 0644 init/postfix-tlspol.service /usr/lib/systemd/system/postfix-tlspol.service
    systemctl daemon-reload
    if systemctl is-enabled postfix-tlspol.service > /dev/null 2>&1; then
      printf "Restarting service unit...$yellow\n"
      systemctl reenable --now postfix-tlspol.service
    else
      printf "Enabling and starting service unit...$yellow\n"
      systemctl enable --now postfix-tlspol.service
    fi
    printf "$rst"
    sleep 0.1
    systemctl status --all --no-pager postfix-tlspol.service
  else
    printf "${red}systemctl not found.$rst\n"
  fi
}

install_docker_app() {
  cd deployments || exit
  if command -v docker > /dev/null 2>&1; then
    docker compose up --build -d
  else
    printf "${red}Docker not found.$rst\n"
  fi
}

read_char() {
  if command -v whiptail > /dev/null 2>&1; then
    eval "$1=$(whiptail --radiolist 'Please select installation method.\nNote that both are compiled from source.\nCheck the README on how to download prebuilt docker images.' 0 0 0 's' 'systemd service unit' 1 'd' 'Docker container' 0 3>&1 1>&2 2>&3)"
  else
    echo "Do you want to install a Docker container or a systemd service? Both a compiled from source. (d/s)"
    old_stty=$(stty -g)
    stty raw -echo min 0 time 150
    eval "$1=$(dd bs=1 count=1 2> /dev/null)"
    stty "$old_stty"
  fi
}

if [ -n "$GITHUB_ACTIONS" ]; then
  act="${act:-"build-only"}"
fi

case "$act" in
  build-only)
    build_go
    exit 0
    ;;
  systemd)
    choice=s
    ;;
  docker)
    choice=d
    ;;
  *)
    read_char choice
    ;;
esac

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
