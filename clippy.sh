#!/usr/bin/env bash

set -e

export RUST_TARGET_PATH="${PWD}/targets"
xargo rustc --lib --release \
  --target x86_64-unknown-none \
  --features clippy \
  -- \
  -C soft-float -C debuginfo=2 \
  -W anonymous-parameters \
  -W trivial-numeric-casts \
  -W unused-extern-crates \
  -W unused-import-braces \
  -W unused-qualifications \
  -W variant-size-differences \
  -Z no-trans -Z extra-plugins=clippy
