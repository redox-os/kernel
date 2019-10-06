#!/usr/bin/env bash

set -e

# https://github.com/rust-lang/rust-clippy/issues/4579
export RUSTUP_TOOLCHAIN="nightly-2019-07-19"
rustup update "${RUSTUP_TOOLCHAIN}"
rustup component add clippy --toolchain "${RUSTUP_TOOLCHAIN}"
rustup component add rust-src --toolchain "${RUSTUP_TOOLCHAIN}"

# Cause recompilation
touch src/lib.rs

export RUST_TARGET_PATH="${PWD}/targets"
export RUSTFLAGS="-C soft-float -C debuginfo=2"
xargo clippy --lib --release --target x86_64-unknown-none
