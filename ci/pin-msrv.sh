#!/bin/bash

set -x
set -euo pipefail

cargo update -p home --precise "0.5.11"
cargo update -p time --precise "0.3.45"
cargo update -p time-core --precise "0.1.7"
