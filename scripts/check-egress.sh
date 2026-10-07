#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --locked -p nm-cli
NETMASTER_DATA_DIR="$(mktemp -d)"
export NETMASTER_DATA_DIR
# mktemp returned an existing directory under the OS temporary directory.
trap 'rm -rf -- "$NETMASTER_DATA_DIR"' EXIT
export PATH="${CARGO_TARGET_DIR:-$PWD/target}/debug:$PATH"
netmaster inventory add fixture.invalid --family airos --name offline-dry-run
netmaster inventory enroll --all-candidates
if command -v unshare >/dev/null && unshare --user --map-root-user --net true 2>/dev/null; then
    unshare --user --map-root-user --net sh -c 'netmaster inventory list && netmaster scan --dry-run && netmaster audit tail'
    echo 'Offline CLI smoke test passed in a network namespace.'
else
    echo 'Network namespaces unavailable; testing the deny-all factory.'
    export NETMASTER_NET=deny
    netmaster inventory list
    netmaster scan --dry-run
    netmaster audit tail
    cargo test --locked -p nm-app --test offline
    cargo test --locked -p nm-collect deny_all_refuses_both_socket_types
fi
# Always exercise the environment-selected deny factory, including when namespace
# isolation is available. The fallback must not be an untested CI-only path.
NETMASTER_NET=deny cargo test --locked -p nm-app --test offline
