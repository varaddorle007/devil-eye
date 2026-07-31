#!/usr/bin/env bash
# Build Devil Eye release with live capture (libpcap) on Linux / macOS.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "$(uname -s)" == "Darwin" ]]; then
  if ! brew list libpcap &>/dev/null; then
    echo "Installing libpcap via Homebrew..."
    brew install libpcap
  fi
  export PKG_CONFIG_PATH="$(brew --prefix libpcap)/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
elif [[ "$(uname -s)" == "Linux" ]]; then
  if ! pkg-config --exists libpcap 2>/dev/null; then
    echo "libpcap not found. Install with:"
    echo "  Debian/Ubuntu: sudo apt-get install -y libpcap-dev pkg-config"
    echo "  Fedora:        sudo dnf install -y libpcap-devel pkgconf"
    echo "  Arch:          sudo pacman -S libpcap"
    exit 1
  fi
fi

cargo build --release
echo ""
echo "Built: ./target/release/devil-eye (live capture enabled)"
echo "Run:   ./target/release/devil-eye"
echo "Live:  sudo ./target/release/devil-eye capture -D"
