#!/bin/sh
###################
#
#  MIT License
#  Copyright (c) 2024-2026 Zuplu
#
#  Calling this script with the env variable NOOPT=1
#  will build a more compatible binary ("NOOPT=1 scripts/build.sh")
#  (i. e. Go toolchain will build for x86_64-v1
#  even if current machine supports v4)
#
#  Set env NOTEST=1 to skip testing (which requires internet access)
#
#  Installation path controls:
#    PREFIX         install root (default "/")
#    BINDIR         binary directory override
#    ETCDIR         config directory override
#    DATADIR        data directory override
#    SYSTEMDUNITDIR systemd unit directory override
#
#  Defaults:
#    PREFIX="/":
#      BINDIR=/usr/bin
#      ETCDIR=/etc/postfix-tlspol
#      DATADIR=/var/lib/postfix-tlspol
#      SYSTEMDUNITDIR=/usr/lib/systemd/system
#
#    PREFIX!="/":
#      BINDIR=$PREFIX/bin
#      ETCDIR=$PREFIX/etc/postfix-tlspol
#      DATADIR=$PREFIX/var/lib/postfix-tlspol
#      SYSTEMDUNITDIR=$PREFIX/usr/lib/systemd/system
#
###################

set -eu

act="${1:-}"

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

log_info() {
  printf "%b\n" "${green}$*${rst}"
}

log_warn() {
  printf "%b\n" "${yellow}$*${rst}"
}

log_error() {
  printf "%b\n" "${red}$*${rst}" >&2
}

log_meta() {
  printf "%b\n" "${cyanbg}$*${rst}"
}

if [ -n "${GITHUB_ACTIONS:-}" ]; then
  act="${act:-build-only}"
  NOTEST="${NOTEST:-1}"
fi

PREFIX="${PREFIX:-/}"
PREFIX="${PREFIX%/}"
if [ -z "$PREFIX" ]; then
  PREFIX="/"
fi

prefix_path() {
  case "$1" in
    /*)
      rel="${1#/}"
      if [ "$PREFIX" = "/" ]; then
        printf "/%s\n" "$rel"
      else
        printf "%s/%s\n" "$PREFIX" "$rel"
      fi
      ;;
    *)
      if [ "$PREFIX" = "/" ]; then
        printf "/%s\n" "$1"
      else
        printf "%s/%s\n" "$PREFIX" "$1"
      fi
      ;;
  esac
}

resolve_dir() {
  # $1 = explicit override (can be empty)
  # $2 = default absolute path
  val="$1"
  def="$2"

  if [ -n "$val" ]; then
    case "$val" in
      /*) printf "%s\n" "$val" ;;
      *) printf "%s\n" "$(prefix_path "$val")" ;;
    esac
  else
    printf "%s\n" "$(prefix_path "$def")"
  fi
}

if [ "$PREFIX" = "/" ]; then
  bindir_default="/usr/bin"
else
  bindir_default="/bin"
fi

BINDIR="$(resolve_dir "${BINDIR:-}" "$bindir_default")"
ETCDIR="$(resolve_dir "${ETCDIR:-}" /etc/postfix-tlspol)"
DATADIR="$(resolve_dir "${DATADIR:-}" /var/lib/postfix-tlspol)"
SYSTEMDUNITDIR="$(resolve_dir "${SYSTEMDUNITDIR:-}" /usr/lib/systemd/system)"

if [ -z "${NOOPT:-}" ]; then
  if [ "$(uname -m)" = "x86_64" ]; then
    detect_goamd64() {
      cpu_flags=""
      if [ -r /proc/cpuinfo ]; then
        cpu_flags=$(
          sed -n -e '/^flags[[:blank:]]*:/ {
          s/^flags[[:blank:]]*:[[:blank:]]*//
          p
          q
        }' /proc/cpuinfo
        )
      fi

      v2_flags="cx16 lahf_lm popcnt sse3|pni sse4_1 sse4_2 ssse3"
      v3_flags="avx avx2 bmi1 bmi2 f16c fma lzcnt|abm movbe xsave"
      v4_flags="avx512f avx512bw avx512cd avx512dq avx512vl"
      max="v1"

      for level in v2 v3 v4; do
        case "$level" in
          v2) req="$v2_flags" ;;
          v3) req="$v2_flags $v3_flags" ;;
          v4) req="$v2_flags $v3_flags $v4_flags" ;;
        esac

        fail=0
        for fg in $req; do
          ok=0
          for alt in $(printf '%s' "$fg" | tr '|' ' '); do
            case " $cpu_flags " in
              *" $alt "*)
                ok=1
                break
                ;;
            esac
          done
          if [ "$ok" -ne 1 ]; then
            fail=1
            break
          fi
        done

        [ "$fail" -eq 0 ] || break
        max="$level"
      done

      if [ -n "${TARGETPLATFORM:-}" ]; then
        if [ "$TARGETPLATFORM" = "linux/amd64" ]; then
          target_platform_norm="linux/amd64/v1"
        else
          target_platform_norm="$TARGETPLATFORM"
        fi

        case "$target_platform_norm" in
          linux/amd64/v[1234])
            req="${target_platform_norm##*/}"
            if [ "${req#v}" -le "${max#v}" ]; then
              echo "$req"
              return 0
            fi
            ;;
        esac
      fi

      echo "$max"
    }

    GOAMD64="$(detect_goamd64)"
    export GOAMD64
  fi
fi

VERSION="${VERSION:-}"
if [ -z "$VERSION" ] && command -v git > /dev/null 2>&1; then
  VERSION="$(git describe --tags --abbrev=0 --match 'v*' 2> /dev/null || true)"
fi
VERSION="${VERSION:-undefined}"
VERSION="${VERSION#v}"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR"

build_go() {
  mkdir -p build

  if ! command -v go > /dev/null 2>&1; then
    log_error "Go toolchain not found. Required unless installing as a Docker container."
    exit 1
  fi

  export GOTOOLCHAIN=auto
  export CGO_ENABLED=0

  log_meta "Version: $VERSION"
  log_info "Install prefix: $PREFIX"
  log_info "BINDIR: $BINDIR"
  log_info "ETCDIR: $ETCDIR"
  log_info "DATADIR: $DATADIR"
  log_info "SYSTEMDUNITDIR: $SYSTEMDUNITDIR"
  log_info "Testing basic functionality..."

  if [ -n "${NOTEST:-}" ]; then
    log_warn "Test skipped."
  else
    # We are only doing a short test here, run scripts/test.sh for a detailed test
    if go test -tags netgo -failfast -short ./...; then
      log_info "Test succeeded."
    else
      log_error "Test failed."
      exit 1
    fi
  fi

  log_info "Building postfix-tlspol..."
  if [ -n "${GOAMD64:-}" ]; then
    log_meta "(Optimized for x86_64-$GOAMD64)"
  fi

  if go build \
    -buildmode=exe \
    -trimpath \
    -tags netgo \
    -ldflags="-d -extldflags='-static' -s -X main.Version=$VERSION" \
    -o build/postfix-tlspol .; then
    log_info "Build succeeded!"
  else
    log_error "Build failed!"
    exit 1
  fi

  install -d -m 0755 "$BINDIR"
  install -d -m 0755 "$ETCDIR"
  install -d -m 0755 "$DATADIR"

  if [ ! -f "$ETCDIR/config.yaml" ]; then
    if [ -f config.yaml ]; then
      # Migrate config.yaml to new directory structure
      mv config.yaml configs/config.yaml
    elif [ ! -f configs/config.yaml ]; then
      # Create scripts/config.yaml from blueprint if it does not exist
      cp -a configs/config.default.yaml configs/config.yaml
    fi

    install -m 0644 configs/config.yaml "$ETCDIR/config.yaml"
    rm -f configs/config.yaml
  fi

  install -m 0755 build/postfix-tlspol "$BINDIR/postfix-tlspol"
}

install_systemd_service() {
  build_go

  if ! command -v systemctl > /dev/null 2>&1; then
    log_error "systemctl not found."
    return 1
  fi

  install -d -m 0755 "$SYSTEMDUNITDIR"
  install -m 0644 init/postfix-tlspol.service "$SYSTEMDUNITDIR/postfix-tlspol.service"

  if [ "$PREFIX" != "/" ]; then
    log_warn "PREFIX is not '/'; installed unit file into staging root only:"
    log_warn "  $SYSTEMDUNITDIR/postfix-tlspol.service"
    log_warn "Skipping daemon-reload/enable/restart on host system."
    return 0
  fi

  systemctl daemon-reload

  if systemctl is-enabled postfix-tlspol.service > /dev/null 2>&1; then
    log_warn "Restarting service unit..."
    systemctl reenable postfix-tlspol.service
    systemctl restart postfix-tlspol.service
  else
    log_warn "Enabling and starting service unit..."
    systemctl enable --now postfix-tlspol.service
  fi

  systemctl status --all --no-pager postfix-tlspol.service
}

install_docker_app() {
  cd deployments || exit 1

  if command -v docker > /dev/null 2>&1; then
    docker compose up --build -d
  else
    log_error "Docker not found."
    return 1
  fi
}

read_char() {
  if command -v whiptail > /dev/null 2>&1; then
    eval "$1=\$(whiptail --radiolist 'Please select installation method.\nNote that both are compiled from source.\nCheck the README on how to download prebuilt docker images.' 0 0 0 's' 'systemd service unit' 1 'd' 'Docker container' 0 3>&1 1>&2 2>&3)"
  else
    printf "%s\n" "Do you want to install a Docker container or a systemd service? Both are compiled from source. (d/s)"
    old_stty="$(stty -g)"
    stty raw -echo min 0 time 150
    eval "$1=\$(dd bs=1 count=1 2> /dev/null)"
    stty "$old_stty"
  fi
}

case "$act" in
  build-only)
    build_go
    exit 0
    ;;
  systemd)
    choice="s"
    ;;
  docker)
    choice="d"
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
