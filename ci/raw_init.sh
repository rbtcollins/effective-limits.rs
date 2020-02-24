#!/bin/sh

set -ex

curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain none -y
. "$HOME"/.cargo/env
rustup -Vv
