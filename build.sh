#!/usr/bin/env bash
#
# build.sh -- one-step build for the Gleam binding. Chains the
# Erlang binding's build.sh (libitb.so + the C binding's static
# archive + the NIF shim) and then compiles the Gleam project; the
# Erlang application is discovered on the code path at runtime by
# the FFI adapter (rebar3 applications are not Gleam packages, so it
# cannot be a gleam.toml dependency). Prerequisites (Go, a C11
# compiler, GNU make, Erlang/OTP 27+, rebar3, Gleam 1.11+) must be
# installed separately; see README.md "Prerequisites".
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm
#   CC=clang ./build.sh    # override the C compiler

set -eu
set -o pipefail

cd "$(dirname "$0")"

../erlang/build.sh "$@"

echo "==> gleam build"
gleam build

echo "==> ready: ./run_tests.sh"
