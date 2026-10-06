#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
violations="$(grep -RIn --include='*.rs' -E '(TcpStream::connect|UdpSocket::bind)' crates | grep -v -E '^crates/nm-collect/src/net\.rs:[0-9]+:' || true)"
if [[ -n "$violations" ]]; then
    printf '%s\n' "$violations"
    echo 'Socket creation must go through nm-collect/src/net.rs.' >&2
    exit 1
fi
echo 'Direct socket creation check passed.'
