#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the Gleam binding:
# compiles the utility's modules with `gleam build` (a no-op when they
# are up to date; libitb3.so, the NIF shim and the Erlang backend are
# assumed built by build.sh) and execs it with every argument passed
# through.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

if [ ! -d "../erlang/_build/default/lib/libitb3/ebin" ]; then
    echo "run_loop.sh: Erlang backend not built, run ./build.sh first" >&2
    exit 1
fi

# Both streams are captured, not just stdout: the build tool reports
# "Compiled in ..." on stderr, and stderr is part of the utility's
# observable contract. A failure still surfaces in full.
if ! build_log=$(gleam build 2>&1); then
    printf '%s\n' "$build_log" >&2
    exit 1
fi

exec ./loop/loop "$@"
