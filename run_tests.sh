#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the Gleam binding.
# Builds libitb.so + the C binding archive + the Erlang backend +
# the Gleam project via build.sh, then invokes `gleam test`.
#
# Usage:
#   ./run_tests.sh

set -eu
set -o pipefail

cd "$(dirname "$0")"

./build.sh

exec gleam test
