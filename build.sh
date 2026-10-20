#!/bin/sh
# Reproducible static build of vpnrelay (x86_64 musl). Same source + Cargo.lock + rustc version -> same bytes, from any
# directory and any host: build paths are remapped, symbols stripped, dependencies locked, and the toolchain's own
# rust-lld links instead of the host's cc/ld (different binutils give different bytes). Prints the SHA-256 to pin.
set -eu
cd "$(dirname "$0")"
here=$(pwd)
RUSTFLAGS="--remap-path-prefix=$here=/build --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo -C strip=symbols -C linker=rust-lld" \
    cargo build --locked --release --target x86_64-unknown-linux-musl
out=target/x86_64-unknown-linux-musl/release/vpnrelay
echo "$(rustc -V)"
echo "$(stat -c %s "$out") bytes"
sha256sum "$out"
