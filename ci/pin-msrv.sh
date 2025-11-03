#!/bin/bash

set -x
set -euo pipefail

cargo update -p home --precise "0.5.11"
