#!/bin/bash

set -ex

export RUST_BACKTRACE=1

rustc -vV
cargo -vV

FEATURES=()
case "$(uname -s)" in
  *NT* ) ;; # Windows NT
  * ) FEATURES+=() ;;
esac

case "$TARGET" in
  # these platforms aren't supported by ring:
  powerpc* ) ;;
  mips* ) ;;
  riscv* ) ;;
  s390x* ) ;;
  aarch64-pc-windows-msvc ) ;;
  # default case, build with rustls enabled
  * ) FEATURES+=() ;;
esac

# rustc only supports armv7: https://doc.rust-lang.org/nightly/rustc/platform-support.html
if [ "$TARGET" = arm-linux-androideabi ]; then
  export CFLAGS='-march=armv7'
fi

cargo build --release --target "$TARGET" "${FEATURES[@]}"

if [ -z "$SKIP_TESTS" ]; then
  cargo test --locked --release --target "$TARGET" "${FEATURES[@]}"
fi
