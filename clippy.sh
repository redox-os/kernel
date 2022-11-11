#!/usr/bin/env bash

set -e

export RUST_TARGET_PATH="${PWD}/targets"
export RUSTFLAGS="-C soft-float -C debuginfo=2"
cargo clippy --lib --release --target x86_64-unknown-none "$@"
