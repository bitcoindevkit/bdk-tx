#!/bin/bash

set -x
set -euo pipefail

# Script to pin dependencies for MSRV

# cargo clean

# rm -f Cargo.lock

# rustup default 1.65.0

cargo update -p zstd-sys --precise "2.0.8+zstd.1.5.5"
cargo update -p time --precise "0.3.20"
cargo update -p home --precise "0.5.5"
cargo update -p flate2 --precise "1.0.35"
cargo update -p once_cell --precise "1.20.3"
cargo update -p bzip2-sys --precise "0.1.12"
cargo update -p ring --precise "0.17.12"
cargo update -p once_cell --precise "1.20.3"
cargo update -p base64ct --precise "1.6.0"
cargo update -p minreq --precise "2.13.2"
