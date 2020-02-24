#!/bin/bash

set -ex

export RUST_BACKTRACE=1

rustc -vV
cargo -vV

# rustc only supports armv7: https://forge.rust-lang.org/release/platform-support.html
if [ "$TARGET" = arm-linux-androideabi ]; then
  export CFLAGS='-march=armv7'
fi

cargo build --release --target "$TARGET"

if [ -z "$SKIP_TESTS" ]; then
  cargo test --locked --release --target "$TARGET"
fi
